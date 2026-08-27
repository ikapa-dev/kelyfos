package graph

import "testing"

func TestSVGScalesGridUnitsToPixels(t *testing.T) {
	l, err := Layout(Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}},
		Edges:  []Edge{{From: "a", To: "b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	opt := SVGOptions{ColStep: 100, RowStep: 50, Margin: 10}
	s := SVG(l, opt)

	if len(s.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(s.Nodes))
	}
	byID := map[string]SVGPoint{}
	for _, n := range s.Nodes {
		byID[n.Node.ID] = n.Pos
	}
	// a is at grid (0,0): pixel (Margin, Margin).
	if got, want := byID["a"], (SVGPoint{X: 10, Y: 10}); got != want {
		t.Errorf("a at %v, want %v", got, want)
	}
	// b is at grid (0,1) (one row below a, same column, per Layout's route
	// for a straight vertical edge): pixel (Margin, Margin+RowStep).
	if got, want := byID["b"], (SVGPoint{X: 10, Y: 60}); got != want {
		t.Errorf("b at %v, want %v", got, want)
	}
}

func TestSVGZeroOptionsUsesDefaults(t *testing.T) {
	l, err := Layout(Input{Agents: []Agent{{ID: "a"}, {ID: "b"}}, Edges: []Edge{{From: "a", To: "b"}}})
	if err != nil {
		t.Fatal(err)
	}
	got := SVG(l, SVGOptions{})
	want := SVG(l, DefaultSVGOptions())
	if len(got.Nodes) != len(want.Nodes) {
		t.Fatalf("node count differs")
	}
	for i := range got.Nodes {
		if got.Nodes[i].Pos != want.Nodes[i].Pos {
			t.Errorf("node %d: zero-options position %v != default-options position %v",
				i, got.Nodes[i].Pos, want.Nodes[i].Pos)
		}
	}
}

func TestSVGWidthHeightCoverEveryNode(t *testing.T) {
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
	opt := SVGOptions{ColStep: 100, RowStep: 50, Margin: 10}
	s := SVG(l, opt)
	for _, n := range s.Nodes {
		if n.Pos.X < 0 || n.Pos.X > s.Width {
			t.Errorf("node %v X=%v outside [0,%v]", n.Node, n.Pos.X, s.Width)
		}
		if n.Pos.Y < 0 || n.Pos.Y > s.Height {
			t.Errorf("node %v Y=%v outside [0,%v]", n.Node, n.Pos.Y, s.Height)
		}
	}
}

func TestSVGEmptyLayout(t *testing.T) {
	s := SVG(Placement{}, DefaultSVGOptions())
	if len(s.Nodes) != 0 || len(s.Edges) != 0 {
		t.Fatalf("expected an empty SVGLayout, got %+v", s)
	}
	opt := DefaultSVGOptions()
	if s.Width != 2*opt.Margin || s.Height != 2*opt.Margin {
		t.Errorf("expected a canvas of exactly 2*Margin on an empty layout, got %vx%v", s.Width, s.Height)
	}
}
