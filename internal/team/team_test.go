package team

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector gathers the broker's events. It locks, because the broker records
// on whichever goroutine delivered the message and says so — a test that
// appends without a lock is testing its own bug.
type collector struct {
	mu sync.Mutex
	ev []Event
}

func (c *collector) record(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ev = append(c.ev, e)
}

func (c *collector) all() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.ev...)
}

func star(t *testing.T) *Topology {
	t.Helper()
	topo, err := NewTopology(
		[]string{"master", "worker-1", "worker-2", "worker-3"},
		[]Edge{{From: "master", To: "worker-*", Bidirectional: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

// The edge list is the topology, so what it permits is the first thing worth
// pinning: a star lets the master reach every worker and lets no worker reach
// another.
func TestStarPermitsTheMasterAndNothingSideways(t *testing.T) {
	topo := star(t)
	for _, w := range []string{"worker-1", "worker-2", "worker-3"} {
		if !topo.Allows("master", w) {
			t.Errorf("master cannot reach %s", w)
		}
		if !topo.Allows(w, "master") {
			t.Errorf("%s cannot reach the master on a bidirectional edge", w)
		}
	}
	if topo.Allows("worker-1", "worker-2") {
		t.Error("a worker can reach a sibling it has no edge to")
	}
	if topo.Allows("worker-1", "worker-1") {
		t.Error("a glob on both sides gave an agent an edge to itself")
	}
}

// A unidirectional edge is visible to the initiating side only, so an agent
// cannot enumerate the team by asking who its peers are.
func TestPeersAreInitiatorSideOnly(t *testing.T) {
	topo, err := NewTopology([]string{"a", "b"}, []Edge{{From: "a", To: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := topo.PeersOf("a"); len(got) != 1 || got[0] != "b" {
		t.Errorf("a's peers = %v, want [b]", got)
	}
	if got := topo.PeersOf("b"); len(got) != 0 {
		t.Errorf("b's peers = %v, want none — the edge is one way", got)
	}
}

// A typo in a topology is not a smaller problem than a typo in an allowlist.
func TestEdgesToNowhereAreRefusedAtBuildTime(t *testing.T) {
	for _, e := range []Edge{
		{From: "master", To: "wroker-*"},
		{From: "nobody", To: "master"},
		{From: "", To: "master"},
	} {
		if _, err := NewTopology([]string{"master", "worker-1"}, []Edge{e}); err == nil {
			t.Errorf("accepted an edge that names nothing: %+v", e)
		}
	}
	if _, err := NewTopology([]string{"a", "a"}, nil); err == nil {
		t.Error("accepted two agents with the same name")
	}
}

func TestSendCrossesAnEdgeAndIsRecorded(t *testing.T) {
	var c collector
	b := New(star(t), false, c.record)

	if err := b.Send("master", "worker-1", []byte("split this")); err != nil {
		t.Fatal(err)
	}
	m, err := b.Recv("worker-1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m.From != "master" || string(m.Body) != "split this" {
		t.Errorf("received %+v", m)
	}
	if len(c.all()) != 1 {
		t.Fatalf("recorded %d events, want 1", len(c.all()))
	}
	e := c.all()[0]
	if e.Type != TypeMessage || e.Outcome != OutcomeDelivered || e.Kind != KindSend {
		t.Errorf("event = %+v", e)
	}
	if e.Bytes != 10 || e.SHA256 == "" {
		t.Errorf("metadata missing: %+v", e)
	}
	// Payload capture is off, so the body must not be in the record.
	if e.Body != "" {
		t.Errorf("the body was recorded with capture off: %q", e.Body)
	}
}

// The refusal is the interesting event, so it has its own type and reaches the
// sender as an error it can act on.
func TestSidewaysSendIsRefusedAndAudited(t *testing.T) {
	var c collector
	b := New(star(t), false, c.record)

	err := b.Send("worker-1", "worker-2", []byte("psst"))
	if err == nil {
		t.Fatal("a worker reached a sibling it has no edge to")
	}
	var te *Error
	if !errors.As(err, &te) || te.Kind != "no_edge" {
		t.Errorf("error = %v, want a no_edge refusal", err)
	}
	if len(c.all()) != 1 || c.all()[0].Type != TypeRefused || c.all()[0].Reason != "no_edge" {
		t.Errorf("events = %+v", c.all())
	}
	// And nothing arrived.
	if _, err := b.Recv("worker-2", 50*time.Millisecond); err == nil {
		t.Error("the refused message was delivered anyway")
	}
}

func TestUnknownAgentIsItsOwnRefusal(t *testing.T) {
	b := New(star(t), false, nil)
	var te *Error
	if err := b.Send("master", "worker-9", []byte("x")); !errors.As(err, &te) || te.Kind != "no_such_agent" {
		t.Errorf("error = %v, want no_such_agent", err)
	}
}

// ask/reply is the primitive agents actually need, and its reply crosses a
// one-way edge without needing an edge of its own.
func TestAskAndReplyOverAUnidirectionalEdge(t *testing.T) {
	topo, err := NewTopology([]string{"asker", "answerer"}, []Edge{{From: "asker", To: "answerer"}})
	if err != nil {
		t.Fatal(err)
	}
	var c collector
	b := New(topo, false, c.record)

	// The answerer has no edge back, and must still be able to answer.
	if b.topo.Allows("answerer", "asker") {
		t.Fatal("the fixture is wrong: this edge is not one-way")
	}
	go func() {
		m, err := b.Recv("answerer", 2*time.Second)
		if err != nil {
			return
		}
		_ = b.Reply("answerer", m.Correlate, []byte("42"))
	}()
	answer, err := b.Ask("asker", "answerer", []byte("how many?"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if string(answer) != "42" {
		t.Errorf("answer = %q", answer)
	}
	if len(c.all()) != 2 || c.all()[0].Kind != KindAsk || c.all()[1].Kind != KindReply {
		t.Errorf("events = %+v", c.all())
	}
}

// A reply is the one path by which a guest could otherwise reach an agent it has
// no edge to, so an unrecognised tag is refused rather than ignored.
func TestAReplyToNothingIsRefused(t *testing.T) {
	var c collector
	b := New(star(t), false, c.record)
	err := b.Reply("worker-1", "deadbeefdeadbeef", []byte("unasked for"))
	if err == nil {
		t.Fatal("a reply with an invented correlation was accepted")
	}
	if len(c.all()) != 1 || c.all()[0].Type != TypeRefused || c.all()[0].Reason != "unknown_correlation" {
		t.Errorf("events = %+v", c.all())
	}
}

// And an agent cannot answer a question that was put to someone else.
func TestOnlyTheAskedAgentMayReply(t *testing.T) {
	b := New(star(t), false, nil)
	go func() {
		m, err := b.Recv("worker-1", time.Second)
		if err != nil {
			return
		}
		// worker-2 tries to answer worker-1's question.
		_ = b.Reply("worker-2", m.Correlate, []byte("not mine to answer"))
	}()
	if _, err := b.Ask("master", "worker-1", []byte("q"), 400*time.Millisecond); err == nil {
		t.Error("a third agent answered a question it was not asked")
	}
}

func TestAskTimesOutRatherThanWaitingForever(t *testing.T) {
	b := New(star(t), false, nil)
	start := time.Now()
	_, err := b.Ask("master", "worker-1", []byte("anyone?"), 200*time.Millisecond)
	if err == nil {
		t.Fatal("an unanswered ask returned successfully")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the timeout took %s to fire", d)
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Errorf("error = %v", err)
	}
}

// Payload capture is a per-team switch, and the digest is there either way so a
// claim about a message can be checked without the log holding a copy of it.
func TestPayloadCaptureIsASwitch(t *testing.T) {
	var c collector
	b := New(star(t), true, c.record)
	if err := b.Send("master", "worker-1", []byte("visible")); err != nil {
		t.Fatal(err)
	}
	if c.all()[0].Body != "visible" {
		t.Errorf("capture was on and the body is %q", c.all()[0].Body)
	}
	if c.all()[0].SHA256 == "" {
		t.Error("no digest even with capture on")
	}
}

// Delivered messages are FIFO per edge.
func TestDeliveryIsFIFOPerEdge(t *testing.T) {
	b := New(star(t), false, nil)
	for _, s := range []string{"one", "two", "three"} {
		if err := b.Send("master", "worker-1", []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"one", "two", "three"} {
		m, err := b.Recv("worker-1", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if string(m.Body) != want {
			t.Fatalf("got %q, want %q — order was not preserved", m.Body, want)
		}
	}
}

// At-most-once means an agent that has stopped reading gets an error, not an
// unbounded amount of someone else's output held on its behalf.
func TestAFullMailboxIsAnErrorNotAQueue(t *testing.T) {
	b := New(star(t), false, nil)
	for i := 0; i < mailbox; i++ {
		if err := b.Send("master", "worker-1", []byte("x")); err != nil {
			t.Fatalf("send %d failed early: %v", i, err)
		}
	}
	err := b.Send("master", "worker-1", []byte("one too many"))
	var te *Error
	if !errors.As(err, &te) || te.Kind != "unreachable" {
		t.Errorf("error = %v, want unreachable", err)
	}
}
