package graph

import "testing"

func TestLayoutEmptyInputIsEmptyLayout(t *testing.T) {
	l, err := Layout(Input{})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Nodes) != 0 || len(l.Edges) != 0 || l.Width != 0 || l.Height != 0 {
		t.Fatalf("expected an empty layout, got %+v", l)
	}
}

func TestLayoutSingleAgentNoEdges(t *testing.T) {
	l, err := Layout(Input{Agents: []Agent{{ID: "solo"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Nodes) != 1 {
		t.Fatalf("expected one node, got %d", len(l.Nodes))
	}
	if got := l.Nodes[0].Pos; got != (Point{0, 0}) {
		t.Errorf("a lone agent should sit at (0,0), got %v", got)
	}
	if l.Width != 1 || l.Height != 1 {
		t.Errorf("expected a 1x1 layout, got %dx%d", l.Width, l.Height)
	}
}

// TestLayoutHubIsAboveEveryWorker checks the star example the task text
// itself names: a hub with bidirectional edges to N workers places the hub
// at the top (row 0) and every worker one row below it, all in the same
// component.
func TestLayoutHubIsAboveEveryWorker(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "hub"}, {ID: "worker-1"}, {ID: "worker-2"}, {ID: "worker-3"}},
		Edges: []Edge{
			{From: "hub", To: "worker-1"}, {From: "worker-1", To: "hub"},
			{From: "hub", To: "worker-2"}, {From: "worker-2", To: "hub"},
			{From: "hub", To: "worker-3"}, {From: "worker-3", To: "hub"},
		},
	}
	l, err := Layout(in)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Point{}
	for _, n := range l.Nodes {
		byID[n.Node.ID] = n.Pos
	}
	if byID["hub"].Y != 0 {
		t.Errorf("hub should be at row 0, got %v", byID["hub"])
	}
	for _, w := range []string{"worker-1", "worker-2", "worker-3"} {
		if byID[w].Y != 1 {
			t.Errorf("%s should be at row 1 (one hop from the hub), got %v", w, byID[w])
		}
		if byID[w].X == byID["hub"].X && byID[w].Y == byID["hub"].Y {
			t.Errorf("%s must not occupy the hub's own position", w)
		}
	}
	// Every worker gets a distinct column.
	seen := map[int]bool{}
	for _, w := range []string{"worker-1", "worker-2", "worker-3"} {
		x := byID[w].X
		if seen[x] {
			t.Errorf("two workers share column %d", x)
		}
		seen[x] = true
	}
}

func TestLayoutDisconnectedAgentsFormSeparateComponents(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}, {ID: "solo"}},
		Edges:  []Edge{{From: "a", To: "b"}},
	}
	l, err := Layout(in)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Point{}
	for _, n := range l.Nodes {
		byID[n.Node.ID] = n.Pos
	}
	// "solo" has no edges, so it must land in its own column band, distinct
	// from a and b's.
	if byID["solo"].X == byID["a"].X && byID["a"].Y == byID["solo"].Y {
		t.Errorf("solo landed on top of a: %v", byID)
	}
}

func TestLayoutPlacesEveryResourceKindOnItsOwnRow(t *testing.T) {
	in := Input{
		Agents: []Agent{{ID: "a"}},
		Resources: []Resource{
			{ID: "github.com", Kind: Domain},
			{ID: "findings/*", Kind: StoreKey},
			{ID: "GITHUB_TOKEN@github.com", Kind: Secret},
		},
		Access: []Access{
			{Agent: "a", Resource: "github.com"},
			{Agent: "a", Resource: "findings/*", Write: true},
			{Agent: "a", Resource: "GITHUB_TOKEN@github.com"},
		},
	}
	l, err := Layout(in)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[ResourceKind]int{}
	for _, n := range l.Nodes {
		if n.Node.Kind == NodeResource {
			rows[n.ResourceKind] = n.Pos.Y
		}
	}
	if rows[Domain] >= rows[StoreKey] || rows[StoreKey] >= rows[Secret] {
		t.Errorf("resource rows must appear in Domain, StoreKey, Secret order; got %v", rows)
	}
	// Every resource must sit strictly below the agent row.
	for _, n := range l.Nodes {
		if n.Node.Kind == NodeAgent && n.Pos.Y >= rows[Domain] {
			t.Errorf("agent row %d is not above the resource rows", n.Pos.Y)
		}
	}
}

func TestLayoutOmitsRowsForAbsentResourceKinds(t *testing.T) {
	in := Input{
		Agents:    []Agent{{ID: "a"}},
		Resources: []Resource{{ID: "GITHUB_TOKEN@github.com", Kind: Secret}},
		Access:    []Access{{Agent: "a", Resource: "GITHUB_TOKEN@github.com"}},
	}
	l, err := Layout(in)
	if err != nil {
		t.Fatal(err)
	}
	// With no Domain and no StoreKey resource, Secret must sit on the row
	// immediately after the agent rows — no blank rows left over for the
	// absent kinds.
	var agentRow, secretRow int
	for _, n := range l.Nodes {
		if n.Node.Kind == NodeAgent {
			agentRow = n.Pos.Y
		} else {
			secretRow = n.Pos.Y
		}
	}
	if secretRow != agentRow+2 { // one gap row, per nodeGap
		t.Errorf("expected the secret row right after the agent row's gap, got agent=%d secret=%d",
			agentRow, secretRow)
	}
}

// TestLayoutIsDeterministicAcrossInputOrder is the property the whole task
// exists to guarantee: the same team, described in a different field order,
// produces byte-identical output.
func TestLayoutIsDeterministicAcrossInputOrder(t *testing.T) {
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

	a, err := Layout(build(false))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Layout(build(true))
	if err != nil {
		t.Fatal(err)
	}
	if Terminal(a).String() != Terminal(b).String() {
		t.Errorf("layout depends on input order:\n--- forward ---\n%s\n--- reversed ---\n%s",
			Terminal(a).String(), Terminal(b).String())
	}
}

func TestLayoutRoutesEveryEdgeAndAccess(t *testing.T) {
	in := Input{
		Agents:    []Agent{{ID: "a"}, {ID: "b"}},
		Edges:     []Edge{{From: "a", To: "b"}},
		Resources: []Resource{{ID: "k", Kind: StoreKey}},
		Access:    []Access{{Agent: "a", Resource: "k", Write: true}},
	}
	l, err := Layout(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Edges) != 2 {
		t.Fatalf("expected 1 routed team edge + 1 routed access edge, got %d", len(l.Edges))
	}
	nodePos := map[NodeID]Point{}
	for _, n := range l.Nodes {
		nodePos[n.Node] = n.Pos
	}
	for _, e := range l.Edges {
		if len(e.Path) < 2 {
			t.Fatalf("routed edge %v has too short a path: %v", e, e.Path)
		}
		if e.Path[0] != nodePos[e.From] {
			t.Errorf("edge path does not start at its From node: %v", e)
		}
		if e.Path[len(e.Path)-1] != nodePos[e.To] {
			t.Errorf("edge path does not end at its To node: %v", e)
		}
	}
}
