package team

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
)

// Store is a team's shared state: a host-side key/blob store with per-key
// access rules, and the answer to a question that has no good answer inside the
// guests.
//
// Two separate facts, with two separate reasons, because they get conflated:
//
//   - Cross-VM shared RAM is impossible here. Firecracker ships no
//     shared-memory device, and that is not an oversight to route around — the
//     minimal device model is the security posture, the same restraint that
//     makes a KelyfOS guest worth trusting.
//   - Two guests cannot mount one ext4 read-write. ext4 is not a cluster
//     filesystem. This is true on any hypervisor and has nothing to do with
//     Firecracker; two kernels writing one block device corrupt it.
//
// Read-only multi-mounting is fine and KelyfOS already relies on it: every fork
// shares one rootfs image. The store is the safe equivalent for state that has
// to change — and unlike either alternative, every access to it is permissioned
// and recorded.
type Store struct {
	mu    sync.RWMutex
	rules []Rule
	data  map[string][]byte
	bytes int

	record func(Event)
	agents []string
}

// Rule grants access to the keys its Name matches. Name, Read and Write all
// accept a trailing "*" glob, the same one edges use.
//
// A key no rule matches is readable and writable by the whole team. A key some
// rule matches is readable and writable only by what that rule lists — so
// adding a rule can only ever narrow access, never widen it, which is the
// direction a policy file should be able to move a permission in.
type Rule struct {
	Name  string
	Read  []string
	Write []string
}

// Limits, because a store with no bound is a way for one agent to make the host
// hold an unbounded amount of data on the team's behalf. Neither is a security
// boundary — the sandbox is that — but a team that hits one gets an error
// instead of a host that has quietly swallowed a gigabyte.
const (
	MaxValueBytes = 1 << 20  // 1 MiB per key
	MaxStoreBytes = 64 << 20 // 64 MiB per team

	// MaxKeyBytes and MaxStoreKeys are what the byte ceilings above did not
	// count (P6-25, finding H-4).
	//
	// MaxStoreBytes weighed len(value) and nothing else, so a key cost an agent
	// nothing against the only budget there was. Ten thousand one-byte keys is
	// ten kilobytes by that arithmetic and ten thousand map entries in fact,
	// and a single key just under MaxValueBytes bought a megabyte of host
	// memory with one byte of value. Both are counted now, and a key has a
	// length of its own: a name is a name, and one longer than a filesystem
	// would accept is not one.
	MaxKeyBytes  = 1 << 10
	MaxStoreKeys = 10_000
)

// Store event, recorded for every access, permitted or not.
const (
	TypeStore = "team.store"

	KindGet = "get"
	KindPut = "put"

	// KindDelete is a put of nothing. It is a separate word in the record
	// because "an agent removed a key" and "an agent wrote an empty value" are
	// the same call and different events, and a transcript that called both
	// `put` would leave a reader to work out which had happened from the byte
	// count (P6-25, finding H-4).
	KindDelete = "delete"
)

// NewStore validates the rules against the team that will use them.
//
// A rule naming an agent that does not exist is an error, for the same reason
// an edge to nowhere is: a typo in an access rule produces a permission nobody
// has and nobody notices until the run that needed it.
func NewStore(topo *Topology, rules []Rule, record func(Event)) (*Store, error) {
	if record == nil {
		record = func(Event) {}
	}
	agents := topo.Agents()
	for _, r := range rules {
		if r.Name == "" {
			return nil, fmt.Errorf("a store rule with no key name matches nothing")
		}
		for _, list := range [][]string{r.Read, r.Write} {
			for _, who := range list {
				if who == "*" {
					continue
				}
				if _, err := expand(who, agents); err != nil {
					return nil, fmt.Errorf("store rule %q names %q: %w", r.Name, who, err)
				}
			}
		}
	}
	return &Store{rules: rules, data: map[string][]byte{}, record: record, agents: agents}, nil
}

// Get reads a key.
func (s *Store) Get(agent, key string) ([]byte, error) {
	// Checked before mayRead, and recorded redacted when it fires, the same
	// way Put's own key_too_long branch does: an oversized key must never
	// reach the record whole, including on the path where the agent would
	// also have been denied for an unrelated reason (S5b).
	if len(key) > MaxKeyBytes {
		s.record(Event{Type: TypeStore, From: agent, To: "", Kind: KindGet,
			Outcome: OutcomeRefused, Reason: "key_too_long"})
		return nil, &Error{Kind: "denied",
			Message: fmt.Sprintf("a store key may be at most %d bytes; this one is %d", MaxKeyBytes, len(key))}
	}
	if !s.mayRead(agent, key) {
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindGet,
			Outcome: OutcomeRefused, Reason: "denied"})
		return nil, &Error{Kind: "denied", Message: denial.TeamStore.Render(
			denial.V{"agent": agent, "verb": "read", "key": key})}
	}
	s.mu.RLock()
	v, ok := s.data[key]
	s.mu.RUnlock()
	if !ok {
		// Absence is not a refusal and must not look like one: an agent that
		// cannot tell "you may not" from "nothing is there" will retry the
		// wrong problem.
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindGet,
			Outcome: OutcomeRefused, Reason: "no_such_key"})
		return nil, &Error{Kind: "not_found", Message: "no value at " + key}
	}
	s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindGet,
		Bytes: len(v), Outcome: OutcomeDelivered})
	return append([]byte(nil), v...), nil
}

// Put writes a key.
func (s *Store) Put(agent, key string, value []byte) error {
	// Checked first, and deliberately before mayWrite: mayWrite's own denial
	// branch records the key in full (To: key), which is right when the key
	// is an ordinary one denied for its own reasons, and wrong when the key
	// is also oversized — an agent should not get the full key back in the
	// record merely because it was ALSO going to be denied for something
	// else. Redacted here (To: "") the same way this check already redacted
	// it when it ran later; only the ordering relative to mayWrite changes
	// (S5b).
	if len(key) > MaxKeyBytes {
		s.record(Event{Type: TypeStore, From: agent, To: "", Kind: KindPut,
			Bytes: len(value), Outcome: OutcomeRefused, Reason: "key_too_long"})
		return &Error{Kind: "denied",
			Message: fmt.Sprintf("a store key may be at most %d bytes; this one is %d", MaxKeyBytes, len(key))}
	}
	if !s.mayWrite(agent, key) {
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindPut,
			Bytes: len(value), Outcome: OutcomeRefused, Reason: "denied"})
		return &Error{Kind: "denied", Message: denial.TeamStore.Render(
			denial.V{"agent": agent, "verb": "write", "key": key})}
	}
	if len(value) > MaxValueBytes {
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindPut,
			Bytes: len(value), Outcome: OutcomeRefused, Reason: "value_too_large"})
		return &Error{Kind: "denied",
			Message: fmt.Sprintf("a store value may be at most %d bytes; this one is %d", MaxValueBytes, len(value))}
	}

	// Writing nothing removes the key, which is the only way an agent has to
	// make the store smaller. Without it the store was append-only for the life
	// of the team: no Delete, no op, no tool, so an agent that filled it had no
	// way to give any of it back and nor did anybody else. This uses the
	// vocabulary that already exists rather than adding an op the guest would
	// have to learn, and docs/teams.md says so.
	if len(value) == 0 {
		s.mu.Lock()
		if old, ok := s.data[key]; ok {
			s.bytes -= len(old) + len(key)
			delete(s.data, key)
		}
		s.mu.Unlock()
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindDelete,
			Outcome: OutcomeDelivered})
		return nil
	}

	s.mu.Lock()
	_, replacing := s.data[key]
	if !replacing && len(s.data) >= MaxStoreKeys {
		s.mu.Unlock()
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindPut,
			Bytes: len(value), Outcome: OutcomeRefused, Reason: "too_many_keys"})
		return &Error{Kind: "denied",
			Message: fmt.Sprintf("this team's store is limited to %d keys; write an empty value to remove one",
				MaxStoreKeys)}
	}
	// The key is weighed with the value. It is held for as long as the entry is,
	// so a budget that ignored it was measuring half of what it was spending.
	grown := s.bytes - len(s.data[key]) + len(value)
	if !replacing {
		grown += len(key)
	}
	if grown > MaxStoreBytes {
		s.mu.Unlock()
		s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindPut,
			Bytes: len(value), Outcome: OutcomeRefused, Reason: "store_full"})
		return &Error{Kind: "denied",
			Message: fmt.Sprintf("this team's store is limited to %d bytes; write an empty value to remove a key",
				MaxStoreBytes)}
	}
	s.data[key] = append([]byte(nil), value...)
	s.bytes = grown
	s.mu.Unlock()

	s.record(Event{Type: TypeStore, From: agent, To: key, Kind: KindPut,
		Bytes: len(value), Outcome: OutcomeDelivered})
	return nil
}

// Keys lists what the store holds. For `team ps` and the transcript, not for an
// agent: nothing in the tool surface enumerates keys, because a key name can
// itself be information one agent has and another does not.
func (s *Store) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.data))
	for k := range s.data {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Store) mayRead(agent, key string) bool  { return s.may(agent, key, false) }
func (s *Store) mayWrite(agent, key string) bool { return s.may(agent, key, true) }

// may answers one access question. The first matching rule decides, so rules
// are read in the order the policy file wrote them and a reader can stop at the
// first line that mentions the key.
func (s *Store) may(agent, key string, write bool) bool {
	for _, r := range s.rules {
		if !globMatch(r.Name, key) {
			continue
		}
		list := r.Read
		if write {
			list = r.Write
		}
		for _, who := range list {
			if who == "*" || globMatch(who, agent) {
				return true
			}
		}
		return false
	}
	// No rule mentions this key, so it belongs to the whole team.
	return true
}

// globMatch is the same trailing-* rule edges use, and deliberately no more.
// A store rule is policy a person writes and another person audits; a full
// pattern language would make the second job harder for no gain.
func globMatch(pattern, s string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(s, prefix)
	}
	return pattern == s
}
