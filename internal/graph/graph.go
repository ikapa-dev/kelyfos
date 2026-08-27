// Package graph is the layout, once (P7-6).
//
// Before this package, a topology existed in three places that each drew it
// differently or not at all: `kelyfos.toml`, the running broker's own
// `Topology` (internal/team), and — once P7-3 lands — the recorded
// `team.topology` event. Three renderers each walking their own copy of the
// same graph is the exact duplication this project has already found twice
// (the MCP argument summarisers at S19, three copies of SafeText by the end
// of P6-3), and a fourth copy here, in whatever renders the reach view, would
// be a third fold on top of the two internal/digest is written to replace
// (P7-1). So this package holds none of those types and imports none of
// those packages. It takes the smallest data a topology can be described
// with — agents, directed edges, resources and who touches them — and is a
// pure function from that to (a) a placement a terminal or an SVG can draw
// and (b) the reachability those edges and resources actually establish. A
// caller — `kelyfos team graph` reading `kelyfos.toml` today, the exported
// report reading a session's fold once P7-1 lands — converts its own domain
// type into an Input and gets back the same answer every other caller would,
// because there is exactly one place this computation happens.
//
// Determinism is not a nicety here, it is the point named in the task text:
// "a layout that moves between two runs of the same team is a diff nobody can
// read." Every function in this package is a pure function of its Input —
// no randomness, no map iteration exposed to an output order, no wall clock.
// The same Input, run twice, in two processes, on two machines, produces
// byte-identical output. That is what makes a golden test possible at all,
// and it is what makes a diff between two reports of the same team meaningful
// instead of noise.
//
// # Why an edge referencing an unknown agent is an error and not a drop
//
// A dangling reference is exactly the kind of caller bug this package must
// never paper over. Dropping it silently would make a reach view UNDERSTATE
// what a team can reach — the one direction a security view must never fail
// in. So Layout and TransitiveClosure both refuse (return an error) on any
// Edge or Access that names an agent or a resource not declared in the same
// Input, and on a duplicate identity (two Agents or two Resources sharing an
// ID). A self-loop edge (From == To) is the one exception: internal/team's
// own topology expander produces those incidentally when a glob overlaps
// itself on both sides ("worker-*" to "worker-*") and silently drops them for
// the same reason ("a glob that overlaps on both sides would otherwise give
// every worker an edge to itself, which means nothing") — this package
// mirrors that precedent rather than inventing a second rule for the same
// case.
//
// # Why only a store key feeds the transitive closure
//
// The reach view answers "what could a compromised agent's output actually
// reach" — the OWASP Agentic AI risk list's transitive privilege inheritance,
// named because a star topology in which every worker reaches every other in
// two hops through the hub is not the isolation it looks like. A declared
// team.edge is one such path. A shared, host-mediated store key is a second,
// quieter one: if agent A may write key K and agent B may read it, A can pass
// B data with no edge between them at all (docs/teams.md §4). An egress
// domain or a bound secret is neither — they are destinations outside the
// team, not state shared between two agents inside it, so two agents allowed
// the same domain do not thereby gain a path to each other through this
// product's own machinery. TransitiveClosure therefore derives its one-hop
// relation from Edges plus write→read pairs on the same StoreKey resource,
// and from nothing else; Layout still places and routes every Access
// regardless of Resource.Kind, because what a reach view must compute and
// what a picture must show are different questions.
package graph

import "fmt"

// AgentID names one team member. It is not validated here — internal/team's
// ValidAgentName is the door that does that, and this package runs on
// already-resolved data, after that door.
type AgentID string

// ResourceID names one resource outside the team's agents: an egress domain,
// a store key, or a bound secret's `name@host`. Also unvalidated here, for
// the same reason.
type ResourceID string

// ResourceKind says what a Resource is, so a reach view can name what was
// crossed rather than only that something was.
type ResourceKind uint8

const (
	Domain ResourceKind = iota
	StoreKey
	Secret
)

func (k ResourceKind) String() string {
	switch k {
	case Domain:
		return "domain"
	case StoreKey:
		return "store_key"
	case Secret:
		return "secret"
	default:
		return "resource"
	}
}

// Agent is one node the layout places for a team member.
//
// Group is the fork-template group a `count` agent expands into
// (docs/teams.md §1.2) — "worker" for worker-1..worker-4 — used only to keep
// a fanned-out group's identity visible on a placed node. Two agents with
// different Group values are never assumed related by this package; grouping
// for layout purposes comes from Edges alone (see Layout's doc comment).
type Agent struct {
	ID    AgentID
	Group string
}

// Edge is one resolved, directed path between two agents — a `[[team.edge]]`
// after any glob has been expanded against the team's actual agent names, the
// way internal/team.Topology already expands one. A bidirectional edge is two
// Edges, one each way: "the edge list IS the topology" (docs/teams.md §1.3)
// and this package draws exactly the edges it is given, nothing implied.
type Edge struct {
	From, To AgentID
}

// Resource is one node outside the team's own agents that an agent can
// touch.
type Resource struct {
	ID   ResourceID
	Kind ResourceKind
}

// Access is one agent's resolved touch on one resource: this agent's
// allowlist covers this domain, this agent is bound to this secret, or this
// agent may read or write this store key — after any glob in the rule that
// granted it (docs/teams.md §4's `read`/`write` lists) is resolved to the
// concrete agent it names. Write is meaningless for Domain and Secret
// resources; callers should leave it false for those.
type Access struct {
	Agent    AgentID
	Resource ResourceID
	Write    bool
}

// Input is everything a Layout or a TransitiveClosure is a pure function of.
// Order within each slice never affects the result — every function in this
// package normalizes and sorts before computing anything, which is what makes
// the output deterministic regardless of the order a caller happened to build
// this in.
type Input struct {
	Agents    []Agent
	Edges     []Edge
	Resources []Resource
	Access    []Access
}

// normalized is Input after validation, deduplication and sorting: the one
// shared view Layout and TransitiveClosure both compute from, so a node that
// exists for one exists identically for the other.
type normalized struct {
	agents    []Agent
	edges     []Edge
	resources []Resource
	access    []Access

	agentIdx map[AgentID]int
	resIdx   map[ResourceID]Resource
}

// normalize validates in and returns a deduplicated, sorted view of it, or an
// error naming the first problem found. See the package doc comment for why
// a dangling reference errors rather than being dropped, and why a self-loop
// edge is the one reference that is silently dropped instead.
func normalize(in Input) (normalized, error) {
	n := normalized{
		agentIdx: make(map[AgentID]int, len(in.Agents)),
		resIdx:   make(map[ResourceID]Resource, len(in.Resources)),
	}

	n.agents = make([]Agent, len(in.Agents))
	copy(n.agents, in.Agents)
	sortAgents(n.agents)
	for i, a := range n.agents {
		if a.ID == "" {
			return normalized{}, fmt.Errorf("graph: an agent with an empty ID cannot be placed")
		}
		if _, dup := n.agentIdx[a.ID]; dup {
			return normalized{}, fmt.Errorf("graph: agent %q is declared twice", a.ID)
		}
		n.agentIdx[a.ID] = i
	}

	n.resources = make([]Resource, len(in.Resources))
	copy(n.resources, in.Resources)
	sortResources(n.resources)
	for _, r := range n.resources {
		if r.ID == "" {
			return normalized{}, fmt.Errorf("graph: a resource with an empty ID cannot be placed")
		}
		if _, dup := n.resIdx[r.ID]; dup {
			return normalized{}, fmt.Errorf("graph: resource %q is declared twice", r.ID)
		}
		n.resIdx[r.ID] = r
	}

	edgeSeen := make(map[Edge]bool, len(in.Edges))
	for _, e := range in.Edges {
		if e.From == e.To {
			// Mirrors internal/team.NewTopology's own handling of a glob that
			// overlaps itself: silently skipped, not an error, because it is
			// an artifact of expansion rather than a caller mistake.
			continue
		}
		if _, ok := n.agentIdx[e.From]; !ok {
			return normalized{}, fmt.Errorf("graph: edge from %q: no such agent", e.From)
		}
		if _, ok := n.agentIdx[e.To]; !ok {
			return normalized{}, fmt.Errorf("graph: edge to %q: no such agent", e.To)
		}
		if edgeSeen[e] {
			continue
		}
		edgeSeen[e] = true
		n.edges = append(n.edges, e)
	}
	sortEdges(n.edges)

	accessSeen := make(map[Access]bool, len(in.Access))
	for _, a := range in.Access {
		if _, ok := n.agentIdx[a.Agent]; !ok {
			return normalized{}, fmt.Errorf("graph: access by %q: no such agent", a.Agent)
		}
		if _, ok := n.resIdx[a.Resource]; !ok {
			return normalized{}, fmt.Errorf("graph: access to %q: no such resource", a.Resource)
		}
		if accessSeen[a] {
			continue
		}
		accessSeen[a] = true
		n.access = append(n.access, a)
	}
	sortAccess(n.access)

	return n, nil
}
