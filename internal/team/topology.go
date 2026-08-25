// Package team implements the host side of KelyfOS agent teams: the topology a
// user declared, the broker that enforces it, and the events both produce.
//
// Everything here runs on the host, and that is the whole design rather than an
// implementation detail. No guest in a team has a network path to any other
// guest (docs/teams.md §2), so every message between agents has to pass through
// this package — which means the edge list cannot be bypassed, and every
// message is auditable, without either property being separately arranged.
package team

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Edge is one declared path between two agents.
type Edge struct {
	From          string
	To            string
	Bidirectional bool
}

// Topology is the edge list, resolved against the agents that actually exist.
//
// Globs are expanded once, here, rather than matched on every message: a
// topology is fixed for the run (docs/teams.md §5), so the set of permitted
// pairs is knowable up front, and knowing it up front is what lets `team ps`
// show the graph and lets a bad edge be rejected at boot instead of at the
// first message.
type Topology struct {
	mu      sync.RWMutex
	agents  []string
	allowed map[string]map[string]bool // from -> to -> true
}

// NewTopology resolves an edge list against a set of agent names.
//
// An edge naming an agent that does not exist is an error rather than a no-op.
// A typo in a topology is not a smaller problem than a typo in an allowlist:
// both produce a machine that silently cannot do what its author wrote down.
// ValidAgentName refuses a name an agent cannot safely be called (P6-26,
// finding M-5).
//
// An agent's name is not only a label. It travels on the guest's **kernel
// command line** as `kelyfos.agent=<name>`, which is the channel the host uses
// precisely because it is the one thing inside the guest the guest did not
// write. That argument holds only while the name cannot carry a space:
// measured, an agent called `worker init=/bin/sh` produced a command line with
// two `init=` parameters, and one called "w\tkelyfos.spawn=1" granted itself a
// spawn budget the host never gave it. The second is not a curiosity about
// kernel arguments — it is a privilege escalation inside the team model.
//
// A name also becomes a directory on the host, a lane in a transcript and a
// column in `team ps`, so the same characters are unwelcome for duller reasons.
//
// Refused rather than sanitised, in the shape P6-24 settled: a name that has to
// be repaired was written to be repaired, and the repaired version is a guess
// about what somebody meant. The person naming their agents is right there,
// reading the error, and can pick another one.
func ValidAgentName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("an agent with an empty name cannot be addressed")
	case len(name) > 64:
		return fmt.Errorf("the agent name %q is %d characters; 64 is the most an agent may be called",
			name[:32]+"…", len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("the agent name %q contains %q. An agent may be named with letters, digits, "+
				"'-', '_' and '.' — the name travels on the guest's kernel command line, where a space would "+
				"start a second parameter the host did not write", name, r)
		}
	}
	return nil
}

func NewTopology(agents []string, edges []Edge) (*Topology, error) {
	known := map[string]bool{}
	for _, a := range agents {
		if err := ValidAgentName(a); err != nil {
			return nil, err
		}
		if known[a] {
			return nil, fmt.Errorf("two agents are both called %q", a)
		}
		known[a] = true
	}
	// A declared agent may not hold the name the host would mint for a worker
	// spawned by another agent *in this team* (P6-27, finding M-6).
	//
	// Such a name is not a duplicate the loop above can see, because the spawn
	// arrives later — and when it does it would land *on top* of the declared
	// agent rather than beside it. Spawn refuses that collision, which is what
	// actually closes the hole; this is the half that reaches the person who can
	// still fix it, in the file they wrote the name in, instead of leaving them
	// a spawn that is refused at runtime for a reason they cannot see.
	//
	// It runs as a second pass because it needs the whole team: the spawner may
	// be declared after its would-be worker. And it sees expanded names rather
	// than written ones, which is what makes it enough — `name = "master-spawn"`
	// with `count = 2` becomes master-spawn-1 before this is called, and it is
	// the expansion that collides, not the name somebody typed.
	//
	// Deliberately no wider than that. Every collidable name is <spawner> +
	// "-spawn-" + a sequence number, so a name whose prefix is nobody in this
	// team can never be minted: `ci-spawn-runner`, `build-spawn-service` and
	// `no-spawn-zone` are ordinary names, and a rule that refused them would
	// have broken team files that were legal, for no collision anybody could
	// have had.
	for _, a := range agents {
		if spawner, ok := mintedSpawnName(a, known); ok {
			return nil, fmt.Errorf("the agent %q is named what the host would call a worker spawned "+
				"by %q, which is also in this team — that spawn would arrive later and land on top of "+
				"this agent, so rename one of the two", a, spawner)
		}
	}
	t := &Topology{agents: append([]string(nil), agents...), allowed: map[string]map[string]bool{}}
	sort.Strings(t.agents)

	for _, e := range edges {
		from, err := expand(e.From, t.agents)
		if err != nil {
			return nil, fmt.Errorf("edge from %q: %w", e.From, err)
		}
		to, err := expand(e.To, t.agents)
		if err != nil {
			return nil, fmt.Errorf("edge to %q: %w", e.To, err)
		}
		for _, f := range from {
			for _, g := range to {
				if f == g {
					// A glob that overlaps on both sides would otherwise give
					// every worker an edge to itself, which means nothing and
					// would show up in team_peers as a peer.
					continue
				}
				t.permit(f, g)
				if e.Bidirectional {
					t.permit(g, f)
				}
			}
		}
	}
	return t, nil
}

// mintedSpawnName reports whether name is one Spawn could ever mint for an
// agent in known — that is, `<spawner>-spawn-<n>` in the exact shape spawn.go
// writes it — and names the spawner if so.
//
// Only the last "-spawn-" can be the minted one: everything after it has to be
// the sequence number, and "-spawn-" is not a number, so an earlier occurrence
// always leaves letters in the tail.
//
// The tail is matched against exactly what spawn.go writes rather than against
// "some digits": the sequence is incremented before it is used, so it starts at
// 1, and %d writes 7 and never 007. `master-spawn-007` is a name no spawn can
// land on, however readily strconv reads its tail as a number.
func mintedSpawnName(name string, known map[string]bool) (string, bool) {
	i := strings.LastIndex(name, "-spawn-")
	if i < 0 {
		return "", false
	}
	spawner, seq := name[:i], name[i+len("-spawn-"):]
	if !known[spawner] {
		return "", false
	}
	n, err := strconv.Atoi(seq)
	if err != nil || n < 1 || strconv.Itoa(n) != seq {
		return "", false
	}
	return spawner, true
}

func (t *Topology) permit(from, to string) {
	if t.allowed[from] == nil {
		t.allowed[from] = map[string]bool{}
	}
	t.allowed[from][to] = true
}

// expand resolves one edge endpoint, which is either an agent name or a
// name-* glob over a count group.
func expand(spec string, agents []string) ([]string, error) {
	if spec == "" {
		return nil, fmt.Errorf("an edge endpoint cannot be empty")
	}
	if prefix, ok := strings.CutSuffix(spec, "*"); ok {
		var out []string
		for _, a := range agents {
			if strings.HasPrefix(a, prefix) {
				out = append(out, a)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("matches no agent in this team")
		}
		return out, nil
	}
	for _, a := range agents {
		if a == spec {
			return []string{spec}, nil
		}
	}
	return nil, fmt.Errorf("no such agent in this team")
}

// attach adds a spawned worker and the single edge it is entitled to.
//
// This is the only mutation a Topology permits, and it exists for E2-5 alone.
// It takes the same lock nothing else needs, because everything else about a
// topology is decided before any agent runs.
func (t *Topology) attach(name, spawner string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.agents = append(t.agents, name)
	sort.Strings(t.agents)
	t.permit(spawner, name)
	t.permit(name, spawner)
}

// detach removes a spawned worker and its edge.
func (t *Topology) detach(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, a := range t.agents {
		if a == name {
			t.agents = append(t.agents[:i:i], t.agents[i+1:]...)
			break
		}
	}
	delete(t.allowed, name)
	for _, to := range t.allowed {
		delete(to, name)
	}
}

// Allows reports whether from may initiate to to.
func (t *Topology) Allows(from, to string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.allowed[from][to]
}

// Exists reports whether an agent is in this team at all, which is a different
// refusal from having no edge and gets a different error.
func (t *Topology) Exists(name string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, a := range t.agents {
		if a == name {
			return true
		}
	}
	return false
}

// Agents lists the team, sorted. For `team ps` and for nothing an agent sees.
func (t *Topology) Agents() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]string(nil), t.agents...)
}

// PeersOf lists the agents this one may *initiate* to, which is deliberately
// not the same as the agents that may reach it. On a unidirectional A → B edge,
// A sees B and B does not see A, so an agent cannot enumerate the team by
// asking who its peers are — it learns its own reach and nothing else
// (docs/teams.md §3.4).
func (t *Topology) PeersOf(agent string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []string
	for to := range t.allowed[agent] {
		out = append(out, to)
	}
	sort.Strings(out)
	return out
}
