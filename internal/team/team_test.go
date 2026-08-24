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
	// One ask and one reply, in either order.
	//
	// The order used to be asserted and it is not the broker's to promise. The
	// ask is recorded by the asking side *after* the message is in the
	// answerer's mailbox — it has to be, because until the send returns nobody
	// knows whether it was delivered or the mailbox was full — so the answerer
	// can wake, reply and record first. Two agents are two processes in a real
	// team, and serialising the broker to make one record land before the other
	// would be paying with the thing the record is about.
	//
	// It failed on CI once before this was written, with the reply first. A test
	// that is usually green is the thing §8 rule 8 exists to be suspicious of.
	kinds := map[string]int{}
	for _, e := range c.all() {
		kinds[e.Kind]++
	}
	if len(c.all()) != 2 || kinds[KindAsk] != 1 || kinds[KindReply] != 1 {
		t.Errorf("events = %+v, want one ask and one reply", c.all())
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

func teamOfThree(t *testing.T) *Topology {
	t.Helper()
	topo, err := NewTopology([]string{"master", "worker-1", "worker-2"},
		[]Edge{{From: "master", To: "worker-*", Bidirectional: true}})
	if err != nil {
		t.Fatal(err)
	}
	return topo
}

// The rules from docs/teams.md §4, and what they must and must not permit.
func TestStoreRulesNarrowAccessAndNeverWidenIt(t *testing.T) {
	var c collector
	s, err := NewStore(teamOfThree(t), []Rule{
		{Name: "findings/*", Write: []string{"worker-*"}, Read: []string{"master"}},
		{Name: "plan", Write: []string{"master"}, Read: []string{"*"}},
	}, c.record)
	if err != nil {
		t.Fatal(err)
	}

	// A worker may write its findings and may not read them back.
	if err := s.Put("worker-1", "findings/a", []byte("x")); err != nil {
		t.Errorf("a worker could not write its own findings: %v", err)
	}
	if _, err := s.Get("worker-1", "findings/a"); err == nil {
		t.Error("a worker read a key only the master may read")
	}
	if _, err := s.Get("master", "findings/a"); err != nil {
		t.Errorf("the master could not read the findings: %v", err)
	}

	// The plan is the master's to write and everyone's to read.
	if err := s.Put("worker-1", "plan", []byte("mine now")); err == nil {
		t.Error("a worker overwrote the plan")
	}
	if err := s.Put("master", "plan", []byte("the plan")); err != nil {
		t.Errorf("the master could not write the plan: %v", err)
	}
	if _, err := s.Get("worker-2", "plan"); err != nil {
		t.Errorf("a worker could not read the plan: %v", err)
	}

	// A key no rule mentions belongs to the whole team.
	if err := s.Put("worker-2", "scratchpad", []byte("free for all")); err != nil {
		t.Errorf("an unlisted key was not open to the team: %v", err)
	}
	if _, err := s.Get("worker-1", "scratchpad"); err != nil {
		t.Errorf("an unlisted key was not readable by the team: %v", err)
	}
}

// Every access is recorded, permitted or not — that is the whole difference
// between shared state and shared state you can account for.
func TestEveryStoreAccessIsRecorded(t *testing.T) {
	var c collector
	s, err := NewStore(teamOfThree(t), []Rule{{Name: "secret", Read: []string{"master"}, Write: []string{"master"}}}, c.record)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Put("master", "secret", []byte("v"))
	_, _ = s.Get("worker-1", "secret")
	_, _ = s.Get("master", "secret")

	ev := c.all()
	if len(ev) != 3 {
		t.Fatalf("recorded %d accesses, want 3: %+v", len(ev), ev)
	}
	if ev[0].Kind != KindPut || ev[0].Outcome != OutcomeDelivered {
		t.Errorf("the write was recorded as %+v", ev[0])
	}
	if ev[1].Outcome != OutcomeRefused || ev[1].Reason != "denied" {
		t.Errorf("the refusal was recorded as %+v", ev[1])
	}
	if ev[2].Outcome != OutcomeDelivered {
		t.Errorf("the permitted read was recorded as %+v", ev[2])
	}
}

// An agent that cannot tell "you may not" from "nothing is there" retries the
// wrong problem, so the two refusals are different.
func TestAbsenceIsNotARefusal(t *testing.T) {
	s, err := NewStore(teamOfThree(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Get("master", "never-written")
	var te *Error
	if !errors.As(err, &te) || te.Kind != "not_found" {
		t.Errorf("error = %v, want not_found", err)
	}
}

func TestStoreRulesNamingNobodyAreRefusedAtBuildTime(t *testing.T) {
	if _, err := NewStore(teamOfThree(t), []Rule{{Name: "k", Read: []string{"wroker-*"}}}, nil); err == nil {
		t.Error("a rule naming no agent was accepted")
	}
	if _, err := NewStore(teamOfThree(t), []Rule{{Name: ""}}, nil); err == nil {
		t.Error("a rule with no key name was accepted")
	}
}

// A store with no bound is a way to make the host hold an unbounded amount of
// data on the team's behalf.
func TestStoreIsBounded(t *testing.T) {
	s, err := NewStore(teamOfThree(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("master", "big", make([]byte, MaxValueBytes+1)); err == nil {
		t.Error("a value over the per-key cap was accepted")
	}
	// Overwriting a key must not count twice toward the total.
	big := make([]byte, MaxValueBytes)
	for i := 0; i < 80; i++ {
		if err := s.Put("master", "same-key", big); err != nil {
			t.Fatalf("overwriting one key ran out of room after %d writes: %v", i, err)
		}
	}
}

// A broker without a store refuses rather than pretending to have lost the data.
func TestABrokerWithNoStoreSaysSo(t *testing.T) {
	b := New(teamOfThree(t), false, nil)
	if _, err := b.StoreGet("master", "k"); err == nil {
		t.Error("a get succeeded on a team with no store")
	}
	if err := b.StorePut("master", "k", []byte("v")); err == nil {
		t.Error("a put succeeded on a team with no store")
	}
}

// The one sanctioned exception to a fixed topology, and everything that keeps
// it narrow.
func TestSpawnNeedsABudgetAndAttachesOneEdge(t *testing.T) {
	var c collector
	b := New(teamOfThree(t), false, c.record)

	// No budget: refused, and audited.
	if _, err := b.Spawn("master", "dev"); err == nil {
		t.Fatal("an agent with no budget spawned a worker")
	}
	if ev := c.all(); len(ev) != 1 || ev[0].Type != TypeSpawn || ev[0].Reason != "no_spawn_budget" {
		t.Errorf("events = %+v", c.all())
	}

	b.GrantSpawn("master", Budget{Max: 2, Images: []string{"dev"}})
	req, err := b.Spawn("master", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if req.Spawner != "master" || req.Image != "dev" {
		t.Errorf("request = %+v", req)
	}

	// Exactly one edge, to its spawner, in both directions — and nothing else.
	if !b.topo.Allows("master", req.Name) || !b.topo.Allows(req.Name, "master") {
		t.Error("the spawned worker is not connected to its spawner")
	}
	for _, other := range []string{"worker-1", "worker-2"} {
		if b.topo.Allows(req.Name, other) || b.topo.Allows(other, req.Name) {
			t.Errorf("the spawned worker has an edge to %s that nobody declared", other)
		}
	}
	// And it can be messaged, which means it got a mailbox.
	if err := b.Send("master", req.Name, []byte("go")); err != nil {
		t.Errorf("the spawned worker cannot be reached: %v", err)
	}
	if m, err := b.Recv(req.Name, time.Second); err != nil || string(m.Body) != "go" {
		t.Errorf("recv = %+v %v", m, err)
	}
}

func TestSpawnBudgetsAreEnforced(t *testing.T) {
	b := New(teamOfThree(t), false, nil)
	b.GrantSpawn("master", Budget{Max: 2, Images: []string{"dev"}})

	first, err := b.Spawn("master", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Spawn("master", "dev"); err != nil {
		t.Fatal(err)
	}
	// Third exceeds max.
	if _, err := b.Spawn("master", "dev"); err == nil {
		t.Error("a spawn beyond the budget's max was allowed")
	}
	// An image outside the whitelist is refused whatever the count.
	b.GrantSpawn("worker-1", Budget{Max: 5, Images: []string{"base"}})
	if _, err := b.Spawn("worker-1", "dev"); err == nil {
		t.Error("an image outside the whitelist was spawned")
	}
	// A budget naming no image permits none: an empty whitelist is empty, not
	// universal, or a half-written policy becomes an open door.
	b.GrantSpawn("worker-2", Budget{Max: 5})
	if _, err := b.Spawn("worker-2", "dev"); err == nil {
		t.Error("a budget with no image list permitted one")
	}

	// Despawning frees a place, and takes the edge with it.
	b.Despawn(first.Name)
	if b.topo.Allows("master", first.Name) {
		t.Error("a despawned worker kept its edge")
	}
	if _, err := b.Spawn("master", "dev"); err != nil {
		t.Errorf("despawning did not free a place in the budget: %v", err)
	}
}

// A spawn budget is granted by the policy file and by nothing else. There is no
// tool for it, and this test exists to keep it that way.
func TestSpawnedWorkersCannotSpawn(t *testing.T) {
	b := New(teamOfThree(t), false, nil)
	b.GrantSpawn("master", Budget{Max: 3, Images: []string{"dev"}})
	req, err := b.Spawn("master", "dev")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Spawn(req.Name, "dev"); err == nil {
		t.Error("a spawned worker inherited the right to spawn")
	}
}
