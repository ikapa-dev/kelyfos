package team

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// Message is one delivery, as the receiving agent sees it.
type Message struct {
	From string
	Body []byte
	// Correlate is set when this is a question. Answering it means calling
	// Reply with this tag; there is no other way to answer, and no way to
	// answer a question that was not asked.
	Correlate string
}

// Event is what the broker asks the caller to record. The broker does not write
// the flight recorder itself: the recorder belongs to the session, the chain is
// the host's, and a package that routes messages has no business also deciding
// what a session's audit trail looks like.
type Event struct {
	Type    string // team.message | team.refused
	From    string
	To      string
	Kind    string // send | ask | reply
	Bytes   int
	SHA256  string
	Body    string // only when the team asked for payload capture
	Reason  string // on a refusal
	Outcome string // delivered | refused | unreachable | timeout
}

// Event types and outcomes, matching docs/teams.md §6.
const (
	TypeMessage = "team.message"
	TypeRefused = "team.refused"

	KindSend  = "send"
	KindAsk   = "ask"
	KindReply = "reply"

	OutcomeDelivered   = "delivered"
	OutcomeRefused     = "refused"
	OutcomeUnreachable = "unreachable"
	OutcomeTimeout     = "timeout"
)

// Broker routes messages between the agents of one team.
//
// Delivery is at-most-once and there is no queue behind it beyond one small
// mailbox per agent: a message to an agent that is gone is an error to the
// sender, not a promise to be kept later (docs/teams.md §3.1). KelyfOS is not
// becoming a message broker with durability guarantees it would then have to
// keep, and the audit log is not the queue in disguise — it records outcomes.
type Broker struct {
	// Store is the team's shared state, or nil for a team without one. Set
	// after New, because a team may have no store and a broker with a nil one
	// should refuse store calls rather than pretend to have lost the data.
	Store *Store

	// OnSpawn boots a worker the broker has already decided may exist. Nil
	// means this team cannot spawn at all — the broker knows what is permitted,
	// and only the host knows how to start a machine.
	OnSpawn func(SpawnRequest) error

	topo    *Topology
	record  func(Event)
	capture bool

	mu        sync.Mutex
	boxes     map[string]chan Message
	pending   map[string]*ask // correlation tag -> the asker waiting
	budgets   map[string]Budget
	spawnedBy map[string][]string
	spawnSeq  int
}

// ask is one outstanding question.
type ask struct {
	from  string
	to    string
	reply chan []byte
}

// mailbox is bounded on purpose. An agent that never calls recv should not be
// able to make the host hold an unbounded amount of another agent's output, and
// a full mailbox is an honest "unreachable" to the sender rather than growth
// nobody asked for.
const mailbox = 64

// New builds a broker over a resolved topology.
//
// record is called for every message and every refusal, on the goroutine that
// delivered it and before the call returns — so it may be called concurrently,
// and must be safe for that. The flight recorder already is: it takes an
// exclusive lock on the session file precisely because several processes write
// one session. Said here because the race detector found the naive version of
// this contract in a test before it could find it in a team.
//
// capture decides whether payloads reach the record at all (docs/teams.md §6).
func New(topo *Topology, capture bool, record func(Event)) *Broker {
	if record == nil {
		record = func(Event) {}
	}
	b := &Broker{topo: topo, record: record, capture: capture,
		boxes: map[string]chan Message{}, pending: map[string]*ask{},
		budgets: map[string]Budget{}, spawnedBy: map[string][]string{}}
	for _, a := range topo.Agents() {
		b.boxes[a] = make(chan Message, mailbox)
	}
	return b
}

// Serve answers one guest's team request. It is the single entry point the
// host's channel server calls, so every op an agent can reach goes through the
// same edge checks and the same record — there is no second door.
//
// The agent name is the host's, taken from the sandbox it came from, never from
// the frame. A guest that could name itself could name someone else.
func (b *Broker) Serve(agent string, req proto.TeamRequest) proto.TeamResponse {
	body, err := base64.StdEncoding.DecodeString(req.Body)
	if err != nil {
		return failed(&Error{Kind: proto.ErrBadRequest, Message: "body is not base64"})
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Minute
	}

	switch req.Op {
	case proto.OpTeamSend:
		if err := b.Send(agent, req.To, body); err != nil {
			return failed(err)
		}
		return proto.TeamResponse{OK: true}

	case proto.OpTeamRecv:
		m, err := b.Recv(agent, timeout)
		if err != nil {
			return failed(err)
		}
		return proto.TeamResponse{OK: true, From: m.From, Correlate: m.Correlate,
			Body: base64.StdEncoding.EncodeToString(m.Body)}

	case proto.OpTeamAsk:
		answer, err := b.Ask(agent, req.To, body, timeout)
		if err != nil {
			return failed(err)
		}
		return proto.TeamResponse{OK: true, Body: base64.StdEncoding.EncodeToString(answer)}

	case proto.OpTeamReply:
		if err := b.Reply(agent, req.Correlate, body); err != nil {
			return failed(err)
		}
		return proto.TeamResponse{OK: true}

	case proto.OpTeamPeers:
		return proto.TeamResponse{OK: true, Peers: b.Peers(agent)}

	case proto.OpTeamStoreGet:
		v, err := b.StoreGet(agent, req.Key)
		if err != nil {
			return failed(err)
		}
		return proto.TeamResponse{OK: true, Body: base64.StdEncoding.EncodeToString(v)}

	case proto.OpTeamStorePut:
		if err := b.StorePut(agent, req.Key, body); err != nil {
			return failed(err)
		}
		return proto.TeamResponse{OK: true}

	case proto.OpTeamSpawn:
		if b.OnSpawn == nil {
			return failed(&Error{Kind: "denied", Message: "this team cannot spawn workers"})
		}
		sreq, err := b.Spawn(agent, req.Image)
		if err != nil {
			return failed(err)
		}
		// The broker decided the worker may exist; the host has to make it. If
		// it cannot, the place in the budget is given back rather than held by
		// a machine that never booted.
		if err := b.OnSpawn(sreq); err != nil {
			b.Despawn(sreq.Name)
			return failed(&Error{Kind: proto.ErrInternal, Message: err.Error()})
		}
		return proto.TeamResponse{OK: true, Agent: sreq.Name}
	}
	return failed(&Error{Kind: proto.ErrBadRequest, Message: "unknown team op " + req.Op})
}

func failed(err error) proto.TeamResponse {
	var te *Error
	if errors.As(err, &te) {
		return proto.TeamResponse{Error: &proto.Error{Kind: te.Kind, Message: te.Message}}
	}
	return proto.TeamResponse{Error: &proto.Error{Kind: proto.ErrInternal, Message: err.Error()}}
}

// Peers is team_peers: what this agent may initiate to, and nothing else.
func (b *Broker) Peers(agent string) []string { return b.topo.PeersOf(agent) }

// Send delivers a message, or explains why it did not.
func (b *Broker) Send(from, to string, body []byte) error {
	return b.deliver(from, to, body, KindSend, "")
}

// Ask delivers a question and waits for its answer.
//
// The correlation tag is minted here and travels with the question; the only
// way to answer is to hand it back. That is what lets a reply cross a
// unidirectional edge without needing an edge of its own: the broker is not
// consulting the topology on the way back, it is completing a call it is
// already holding open (docs/teams.md §3.3).
func (b *Broker) Ask(from, to string, body []byte, timeout time.Duration) ([]byte, error) {
	tag, err := newTag()
	if err != nil {
		return nil, err
	}
	a := &ask{from: from, to: to, reply: make(chan []byte, 1)}
	b.mu.Lock()
	b.pending[tag] = a
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, tag)
		b.mu.Unlock()
	}()

	if err := b.deliver(from, to, body, KindAsk, tag); err != nil {
		return nil, err
	}
	select {
	case answer := <-a.reply:
		return answer, nil
	case <-time.After(timeout):
		b.record(Event{Type: TypeMessage, From: to, To: from, Kind: KindReply,
			Outcome: OutcomeTimeout})
		return nil, &Error{Kind: "timeout",
			Message: fmt.Sprintf("%s did not answer within %s", to, timeout)}
	}
}

// Reply answers a question by its tag.
func (b *Broker) Reply(from, tag string, body []byte) error {
	b.mu.Lock()
	a, ok := b.pending[tag]
	b.mu.Unlock()
	// An unrecognised tag is refused rather than ignored. It is the one path by
	// which a guest could otherwise reach an agent it has no edge to — answer a
	// question nobody asked it — so it is checked, and checked against the
	// agent the question actually went to.
	if !ok || a.to != from {
		b.record(Event{Type: TypeRefused, From: from, Kind: KindReply,
			Reason: "unknown_correlation", Outcome: OutcomeRefused})
		return &Error{Kind: "denied", Message: "no question is outstanding with that correlation"}
	}
	b.record(b.describe(from, a.from, body, KindReply, OutcomeDelivered, ""))
	select {
	case a.reply <- body:
	default:
	}
	return nil
}

// StoreGet and StorePut are the broker's face on the team store, so a guest
// reaches everything through one channel and one set of refusals.
func (b *Broker) StoreGet(agent, key string) ([]byte, error) {
	if b.Store == nil {
		return nil, &Error{Kind: "denied", Message: "this team has no store"}
	}
	return b.Store.Get(agent, key)
}

func (b *Broker) StorePut(agent, key string, value []byte) error {
	if b.Store == nil {
		return &Error{Kind: "denied", Message: "this team has no store"}
	}
	return b.Store.Put(agent, key, value)
}

// Recv takes the next message for an agent.
func (b *Broker) Recv(agent string, timeout time.Duration) (Message, error) {
	b.mu.Lock()
	box, ok := b.boxes[agent]
	b.mu.Unlock()
	if !ok {
		return Message{}, &Error{Kind: "no_such_agent", Message: agent + " is not in this team"}
	}
	select {
	case m := <-box:
		return m, nil
	case <-time.After(timeout):
		return Message{}, &Error{Kind: "timeout", Message: "nothing arrived within " + timeout.String()}
	}
}

// deliver is the one path every message takes, so the edge check and the record
// cannot be skipped by adding a new entry point later.
func (b *Broker) deliver(from, to string, body []byte, kind, correlate string) error {
	switch {
	case !b.topo.Exists(to):
		b.record(b.describe(from, to, body, kind, OutcomeRefused, "no_such_agent"))
		return &Error{Kind: "no_such_agent", Message: to + " is not in this team"}
	case !b.topo.Allows(from, to):
		b.record(b.describe(from, to, body, kind, OutcomeRefused, "no_edge"))
		return &Error{Kind: "no_edge",
			Message: fmt.Sprintf("this team has no edge from %s to %s", from, to)}
	}

	b.mu.Lock()
	box := b.boxes[to]
	b.mu.Unlock()
	select {
	case box <- Message{From: from, Body: body, Correlate: correlate}:
		b.record(b.describe(from, to, body, kind, OutcomeDelivered, ""))
		return nil
	default:
		// Full mailbox, or an agent that has stopped reading. Either way the
		// message is not delivered and the sender is told so — nothing is held
		// for a machine that may never come back.
		b.record(b.describe(from, to, body, kind, OutcomeUnreachable, "mailbox_full"))
		return &Error{Kind: "unreachable", Message: to + " is not reading its messages"}
	}
}

// describe builds the event for one message. Metadata always; the payload only
// when the team asked for it, and a digest either way so a later claim about
// what was sent can be checked without the log holding a second copy of it.
func (b *Broker) describe(from, to string, body []byte, kind, outcome, reason string) Event {
	sum := sha256.Sum256(body)
	e := Event{
		Type: TypeMessage, From: from, To: to, Kind: kind,
		Bytes: len(body), SHA256: hex.EncodeToString(sum[:]), Outcome: outcome, Reason: reason,
	}
	if outcome == OutcomeRefused {
		e.Type = TypeRefused
	}
	if b.capture {
		e.Body = string(body)
	}
	return e
}

// Error is a refusal an agent receives and can act on. Every one of them is a
// kind from docs/teams.md §3.6; there is no silent drop anywhere in this file.
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string { return e.Kind + ": " + e.Message }

func newTag() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint a correlation tag: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
