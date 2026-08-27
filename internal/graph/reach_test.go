package graph

import "testing"

// TestStarTopologyIsNotIsolation is the exact scenario the task text and the
// package doc comment both name: a hub with a bidirectional edge to every
// worker looks, edge by edge, like each worker is isolated from the others —
// no edge names two workers together anywhere. It is not isolation, because
// the hub relays: every worker reaches every other worker in exactly two
// hops. A reach view that only checked "is there a direct edge" would call
// this isolation and be wrong.
func TestStarTopologyIsNotIsolation(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "hub"}, {ID: "worker-1"}, {ID: "worker-2"}, {ID: "worker-3"}},
		Edges: []Edge{
			{From: "hub", To: "worker-1"}, {From: "worker-1", To: "hub"},
			{From: "hub", To: "worker-2"}, {From: "worker-2", To: "hub"},
			{From: "hub", To: "worker-3"}, {From: "worker-3", To: "hub"},
		},
	}
	c, err := TransitiveClosure(in)
	if err != nil {
		t.Fatal(err)
	}

	if !c.Reaches("worker-1", "worker-2") {
		t.Error("worker-1 must reach worker-2 through the hub, and does not")
	}
	if hops, ok := c.HopsBetween("worker-1", "worker-2"); !ok || hops != 2 {
		t.Errorf("worker-1 → worker-2 should be exactly 2 hops (through the hub), got hops=%d ok=%v",
			hops, ok)
	}
	for _, pair := range [][2]AgentID{
		{"worker-1", "worker-3"}, {"worker-2", "worker-1"},
		{"worker-2", "worker-3"}, {"worker-3", "worker-1"}, {"worker-3", "worker-2"},
	} {
		if !c.Reaches(pair[0], pair[1]) {
			t.Errorf("%s should reach %s through the hub", pair[0], pair[1])
		}
	}
	if c.Reaches("worker-1", "worker-1") {
		t.Error("an agent does not 'reach' itself")
	}
}

// TestUnidirectionalStarDoesNotGiveWorkersEachOther confirms the closure
// respects direction: if workers may only send TO the hub (not receive from
// it), the hub still can't relay anything back to a peer, because the hub
// never has an edge to any worker.
func TestUnidirectionalStarDoesNotGiveWorkersEachOther(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "hub"}, {ID: "worker-1"}, {ID: "worker-2"}},
		Edges: []Edge{
			{From: "worker-1", To: "hub"},
			{From: "worker-2", To: "hub"},
		},
	}
	c, err := TransitiveClosure(in)
	if err != nil {
		t.Fatal(err)
	}
	if c.Reaches("worker-1", "worker-2") {
		t.Error("worker-1 must not reach worker-2: the hub has no edge back to anyone")
	}
	if !c.Reaches("worker-1", "hub") {
		t.Error("worker-1 should still reach the hub directly")
	}
}

// TestSharedStoreKeyOpensAnIndirectChannel is the second path P7-6's package
// doc comment names: no edge at all, but agent a may write a key agent b may
// read, so a can pass b data through the store the way an edge would let it
// message b directly.
func TestSharedStoreKeyOpensAnIndirectChannel(t *testing.T) {
	in := Input{
		Agents:    []Agent{{ID: "worker"}, {ID: "master"}},
		Resources: []Resource{{ID: "findings/*", Kind: StoreKey}},
		Access: []Access{
			{Agent: "worker", Resource: "findings/*", Write: true},
			{Agent: "master", Resource: "findings/*", Write: false},
		},
	}
	c, err := TransitiveClosure(in)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Reaches("worker", "master") {
		t.Error("the writer should reach the reader through the shared store key")
	}
	if c.Reaches("master", "worker") {
		t.Error("the reader must not reach the writer — nothing routes that direction")
	}
}

// TestDomainAndSecretAccessDoNotOpenAChannel is the boundary the package doc
// comment draws explicitly: an egress domain or a bound secret is a
// destination outside the team, not shared state between two agents inside
// it, so two agents both allowed the same domain gain no path to each other
// through this closure.
func TestDomainAndSecretAccessDoNotOpenAChannel(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}},
		Resources: []Resource{
			{ID: "github.com", Kind: Domain},
			{ID: "TOKEN@github.com", Kind: Secret},
		},
		Access: []Access{
			{Agent: "a", Resource: "github.com"},
			{Agent: "b", Resource: "github.com"},
			{Agent: "a", Resource: "TOKEN@github.com"},
			{Agent: "b", Resource: "TOKEN@github.com"},
		},
	}
	c, err := TransitiveClosure(in)
	if err != nil {
		t.Fatal(err)
	}
	if c.Reaches("a", "b") || c.Reaches("b", "a") {
		t.Error("a shared domain or secret must not create a reach path between two agents")
	}
}

func TestClosureChainsThroughMultipleHops(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}},
		Edges: []Edge{
			{From: "a", To: "b"},
			{From: "b", To: "c"},
			{From: "c", To: "d"},
		},
	}
	c, err := TransitiveClosure(in)
	if err != nil {
		t.Fatal(err)
	}
	if hops, ok := c.HopsBetween("a", "d"); !ok || hops != 3 {
		t.Errorf("a → d should be 3 hops down the chain, got hops=%d ok=%v", hops, ok)
	}
	if c.Reaches("d", "a") {
		t.Error("the chain is one-directional; d must not reach a")
	}
	got := c.ReachableFrom("a")
	want := []AgentID{"b", "c", "d"}
	if len(got) != len(want) {
		t.Fatalf("ReachableFrom(a) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ReachableFrom(a) = %v, want %v", got, want)
		}
	}
}

func TestClosureUnknownAgentIsNotReachableAndDoesNotPanic(t *testing.T) {
	c, err := TransitiveClosure(Input{Agents: []Agent{{ID: "a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Reaches("a", "ghost") || c.Reaches("ghost", "a") {
		t.Error("an unknown agent must never be reported reachable")
	}
	if _, ok := c.HopsBetween("ghost", "ghost"); ok {
		t.Error("an unknown agent must never be reported reachable, even from itself")
	}
	if got := c.ReachableFrom("ghost"); got != nil {
		t.Errorf("ReachableFrom on an unknown agent should be empty, got %v", got)
	}
}

func TestClosureIsDeterministicAcrossInputOrder(t *testing.T) {
	build := func(reversed bool) Input {
		agents := []Agent{{ID: "hub"}, {ID: "worker-1"}, {ID: "worker-2"}}
		edges := []Edge{
			{From: "hub", To: "worker-1"}, {From: "worker-1", To: "hub"},
			{From: "hub", To: "worker-2"}, {From: "worker-2", To: "hub"},
		}
		if reversed {
			for i, j := 0, len(agents)-1; i < j; i, j = i+1, j-1 {
				agents[i], agents[j] = agents[j], agents[i]
			}
			for i, j := 0, len(edges)-1; i < j; i, j = i+1, j-1 {
				edges[i], edges[j] = edges[j], edges[i]
			}
		}
		return Input{Agents: agents, Edges: edges}
	}
	a, err := TransitiveClosure(build(false))
	if err != nil {
		t.Fatal(err)
	}
	b, err := TransitiveClosure(build(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Agents) != len(b.Agents) {
		t.Fatalf("agent count differs: %d vs %d", len(a.Agents), len(b.Agents))
	}
	for i := range a.Agents {
		if a.Agents[i] != b.Agents[i] {
			t.Fatalf("agent order depends on input order at %d: %q vs %q", i, a.Agents[i], b.Agents[i])
		}
		for j := range a.Agents {
			if a.Hops[i][j] != b.Hops[i][j] {
				t.Errorf("Hops[%d][%d] depends on input order: %d vs %d", i, j, a.Hops[i][j], b.Hops[i][j])
			}
		}
	}
}
