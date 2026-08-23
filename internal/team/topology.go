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
	"strings"
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
	agents  []string
	allowed map[string]map[string]bool // from -> to -> true
}

// NewTopology resolves an edge list against a set of agent names.
//
// An edge naming an agent that does not exist is an error rather than a no-op.
// A typo in a topology is not a smaller problem than a typo in an allowlist:
// both produce a machine that silently cannot do what its author wrote down.
func NewTopology(agents []string, edges []Edge) (*Topology, error) {
	known := map[string]bool{}
	for _, a := range agents {
		if a == "" {
			return nil, fmt.Errorf("an agent with an empty name cannot be addressed")
		}
		if known[a] {
			return nil, fmt.Errorf("two agents are both called %q", a)
		}
		known[a] = true
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

// Allows reports whether from may initiate to to.
func (t *Topology) Allows(from, to string) bool {
	return t.allowed[from][to]
}

// Exists reports whether an agent is in this team at all, which is a different
// refusal from having no edge and gets a different error.
func (t *Topology) Exists(name string) bool {
	for _, a := range t.agents {
		if a == name {
			return true
		}
	}
	return false
}

// Agents lists the team, sorted. For `team ps` and for nothing an agent sees.
func (t *Topology) Agents() []string { return append([]string(nil), t.agents...) }

// PeersOf lists the agents this one may *initiate* to, which is deliberately
// not the same as the agents that may reach it. On a unidirectional A → B edge,
// A sees B and B does not see A, so an agent cannot enumerate the team by
// asking who its peers are — it learns its own reach and nothing else
// (docs/teams.md §3.4).
func (t *Topology) PeersOf(agent string) []string {
	var out []string
	for to := range t.allowed[agent] {
		out = append(out, to)
	}
	sort.Strings(out)
	return out
}
