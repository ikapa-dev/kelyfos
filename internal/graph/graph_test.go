package graph

import (
	"strings"
	"testing"
)

func TestNormalizeRejectsDuplicateAgent(t *testing.T) {
	_, err := normalize(Input{Agents: []Agent{{ID: "a"}, {ID: "a"}}})
	if err == nil {
		t.Fatal("expected an error for a duplicate agent ID, got none")
	}
	if !strings.Contains(err.Error(), "declared twice") {
		t.Errorf("error %q does not name the actual problem", err)
	}
}

func TestNormalizeRejectsDuplicateResource(t *testing.T) {
	_, err := normalize(Input{Resources: []Resource{
		{ID: "github.com", Kind: Domain},
		{ID: "github.com", Kind: StoreKey},
	}})
	if err == nil {
		t.Fatal("expected an error for a duplicate resource ID, got none")
	}
}

func TestNormalizeRejectsEmptyIdentity(t *testing.T) {
	if _, err := normalize(Input{Agents: []Agent{{ID: ""}}}); err == nil {
		t.Error("expected an error for an empty agent ID")
	}
	if _, err := normalize(Input{Resources: []Resource{{ID: ""}}}); err == nil {
		t.Error("expected an error for an empty resource ID")
	}
}

func TestNormalizeRejectsEdgeToUnknownAgent(t *testing.T) {
	_, err := normalize(Input{
		Agents: []Agent{{ID: "a"}},
		Edges:  []Edge{{From: "a", To: "ghost"}},
	})
	if err == nil {
		t.Fatal("expected an error for an edge naming an agent that was never declared")
	}
	_, err = normalize(Input{
		Agents: []Agent{{ID: "a"}},
		Edges:  []Edge{{From: "ghost", To: "a"}},
	})
	if err == nil {
		t.Fatal("expected an error for an edge FROM an agent that was never declared")
	}
}

func TestNormalizeRejectsAccessToUnknownAgentOrResource(t *testing.T) {
	agents := []Agent{{ID: "a"}}
	resources := []Resource{{ID: "k", Kind: StoreKey}}

	if _, err := normalize(Input{Agents: agents, Resources: resources,
		Access: []Access{{Agent: "ghost", Resource: "k"}}}); err == nil {
		t.Error("expected an error for access by an agent that was never declared")
	}
	if _, err := normalize(Input{Agents: agents, Resources: resources,
		Access: []Access{{Agent: "a", Resource: "ghost"}}}); err == nil {
		t.Error("expected an error for access to a resource that was never declared")
	}
}

// A dangling reference must error rather than be dropped — the package doc
// comment explains why: dropping it would make a reach view UNDERSTATE what
// a team can reach, the one direction this must never fail silently in.
// TestNormalizeNeverDropsADanglingReference exists so a future edit that
// "helpfully" starts skipping unknown IDs instead of refusing them is caught
// here rather than found later as a reach matrix that under-reports.
func TestNormalizeNeverDropsADanglingReference(t *testing.T) {
	_, err := Layout(Input{
		Agents: []Agent{{ID: "a"}},
		Edges:  []Edge{{From: "a", To: "ghost"}},
	})
	if err == nil {
		t.Fatal("Layout silently accepted a dangling edge instead of refusing it")
	}
	_, err = TransitiveClosure(Input{
		Agents: []Agent{{ID: "a"}},
		Edges:  []Edge{{From: "a", To: "ghost"}},
	})
	if err == nil {
		t.Fatal("TransitiveClosure silently accepted a dangling edge instead of refusing it")
	}
}

func TestNormalizeDropsSelfLoopSilently(t *testing.T) {
	n, err := normalize(Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}},
		Edges:  []Edge{{From: "a", To: "a"}, {From: "a", To: "b"}},
	})
	if err != nil {
		t.Fatalf("a self-loop edge must be dropped, not refused: %v", err)
	}
	if len(n.edges) != 1 || n.edges[0] != (Edge{From: "a", To: "b"}) {
		t.Errorf("expected only a→b to survive, got %v", n.edges)
	}
}

func TestNormalizeDedupesEdgesAndAccess(t *testing.T) {
	n, err := normalize(Input{
		Agents:    []Agent{{ID: "a"}, {ID: "b"}},
		Edges:     []Edge{{From: "a", To: "b"}, {From: "a", To: "b"}},
		Resources: []Resource{{ID: "k", Kind: StoreKey}},
		Access: []Access{
			{Agent: "a", Resource: "k", Write: true},
			{Agent: "a", Resource: "k", Write: true},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(n.edges) != 1 {
		t.Errorf("expected duplicate edges to collapse to one, got %d", len(n.edges))
	}
	if len(n.access) != 1 {
		t.Errorf("expected duplicate access records to collapse to one, got %d", len(n.access))
	}
}

func TestNormalizeIsOrderIndependent(t *testing.T) {
	agentsA := []Agent{{ID: "b"}, {ID: "a"}, {ID: "c"}}
	agentsB := []Agent{{ID: "c"}, {ID: "a"}, {ID: "b"}}

	na, err := normalize(Input{Agents: agentsA})
	if err != nil {
		t.Fatal(err)
	}
	nb, err := normalize(Input{Agents: agentsB})
	if err != nil {
		t.Fatal(err)
	}
	if len(na.agents) != len(nb.agents) {
		t.Fatalf("length mismatch: %d vs %d", len(na.agents), len(nb.agents))
	}
	for i := range na.agents {
		if na.agents[i].ID != nb.agents[i].ID {
			t.Errorf("agent order depends on input order at %d: %q vs %q",
				i, na.agents[i].ID, nb.agents[i].ID)
		}
	}
}
