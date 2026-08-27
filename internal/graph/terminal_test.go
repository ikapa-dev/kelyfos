package graph

import (
	"strings"
	"testing"
)

func TestTerminalEmptyLayout(t *testing.T) {
	c := Terminal(Placement{})
	if len(c.Cells) != 0 || len(c.Legend) != 0 || len(c.Edges) != 0 {
		t.Fatalf("expected an empty canvas, got %+v", c)
	}
	if c.String() != "" {
		t.Errorf("expected an empty string, got %q", c.String())
	}
}

func TestTerminalStringTrimsTrailingSpace(t *testing.T) {
	l, err := Layout(Input{Agents: []Agent{{ID: "solo"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := Terminal(l)
	for _, line := range strings.Split(c.String(), "\n") {
		if strings.HasSuffix(line, " ") {
			t.Errorf("line %q has untrimmed trailing space", line)
		}
	}
}

func TestTerminalPlacesAGlyphAtEveryNode(t *testing.T) {
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
	c := Terminal(l)
	if len(c.Legend) != 3 {
		t.Fatalf("expected 3 legend entries (2 agents + 1 resource), got %d", len(c.Legend))
	}
	if len(c.Edges) != len(l.Edges) {
		t.Fatalf("Canvas.Edges should be a straight projection of the Placement's own edges: "+
			"got %d, want %d", len(c.Edges), len(l.Edges))
	}
	for i, e := range l.Edges {
		if c.Edges[i] != (TerminalEdge{From: e.From, To: e.To, Kind: e.Kind}) {
			t.Errorf("Canvas.Edges[%d] = %+v, want the same From/To/Kind as l.Edges[%d] = %+v",
				i, c.Edges[i], i, e)
		}
	}
	for _, entry := range c.Legend {
		got := c.Cells[entry.Row][entry.Col]
		want := rune(0)
		switch entry.Node.Kind {
		case NodeAgent:
			want = '●'
		case NodeResource:
			want = '■' // StoreKey
		}
		if got != want {
			t.Errorf("node %v: expected glyph %q at (%d,%d), got %q",
				entry.Node, want, entry.Row, entry.Col, got)
		}
	}
}

func TestGlyphForDistinguishesResourceKinds(t *testing.T) {
	cases := []struct {
		kind ResourceKind
		want rune
	}{
		{Domain, '◆'},
		{StoreKey, '■'},
		{Secret, '▲'},
	}
	for _, c := range cases {
		n := PlacedNode{Node: NodeID{Kind: NodeResource}, ResourceKind: c.kind}
		if got := glyphFor(n); got != c.want {
			t.Errorf("glyphFor(%v) = %q, want %q", c.kind, got, c.want)
		}
	}
	agent := PlacedNode{Node: NodeID{Kind: NodeAgent}}
	if got := glyphFor(agent); got != '●' {
		t.Errorf("glyphFor(agent) = %q, want '●'", got)
	}
}

// TestCornerGlyphAllFourBends checks the box-drawing character chosen at
// every one of the four ways a two-segment, axis-aligned path can bend —
// hand-verified against what each character actually draws, rather than
// against this function's own logic.
func TestCornerGlyphAllFourBends(t *testing.T) {
	cases := []struct {
		name          string
		prev, b, next Point
		want          rune
	}{
		// prev is above b (arm north), next is to the right (arm east):
		// the glyph needs a stroke going up and a stroke going right.
		{"north-then-east", Point{0, 0}, Point{0, 1}, Point{1, 1}, '└'},
		// prev is above b (arm north), next is to the left (arm west).
		{"north-then-west", Point{1, 0}, Point{1, 1}, Point{0, 1}, '┘'},
		// prev is below b (arm south), next is to the right (arm east).
		{"south-then-east", Point{0, 1}, Point{0, 0}, Point{1, 0}, '┌'},
		// prev is below b (arm south), next is to the left (arm west).
		{"south-then-west", Point{1, 1}, Point{1, 0}, Point{0, 0}, '┐'},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cornerGlyph(c.prev, c.b, c.next); got != c.want {
				t.Errorf("cornerGlyph(%v,%v,%v) = %q, want %q", c.prev, c.b, c.next, got, c.want)
			}
		})
	}
}

// TestDrawSegmentNeverOverwritesAGlyph guards a narrower invariant than its
// name alone suggests: drawSegment itself never overwrites a rune another
// call already wrote — a crossing keeps whichever edge's segment reached
// that cell first, rather than one silently clobbering another's glyph.
//
// This does NOT mean a crossing can never be misread as a connection that
// does not exist. It very much can: a routed edge's corner is chosen from
// one endpoint's column and the other's row (route, layout.go), so that
// corner often lands exactly on a third node's own cell, and that node's
// glyph is drawn last and overwrites whatever the corner was — at which
// point Cells alone can show two nodes as joined by a line that is actually
// two unrelated edges meeting behind a third node's back. Canvas.Cells is
// documented as a sketch for exactly this reason; Canvas.Edges is what is
// authoritative. See TestCanvasEdgesAreAuthoritativeEvenWhenCellsCollide,
// which demonstrates the collision this comment used to (wrongly) say could
// not happen.
func TestDrawSegmentNeverOverwritesAGlyph(t *testing.T) {
	// One grid step (colStep runes) between the two endpoints, so the whole
	// scaled span fits in the row.
	cells := [][]rune{make([]rune, colStep+1)}
	for i := range cells[0] {
		cells[0][i] = ' '
	}
	cells[0][0] = '●'
	drawSegment(cells, Point{0, 0}, Point{1, 0})
	if cells[0][0] != '●' {
		t.Errorf("drawSegment overwrote an existing glyph: %q", cells[0][0])
	}
	for i := 1; i < len(cells[0]); i++ {
		if cells[0][i] != '─' {
			t.Errorf("expected '─' at column %d, got %q", i, cells[0][i])
		}
	}
}

// TestCanvasEdgesAreAuthoritativeEvenWhenCellsCollide is the fix for the
// review finding that Terminal's rune drawing can make two genuinely
// different topologies indistinguishable: a star (a↔b, a↔c, no b-c edge) and
// a chain (a↔b, b↔c, no a-c edge) render byte-identical Cells, because the
// star's a→c edge bends through b's own cell and vanishes under b's glyph,
// leaving what reads as one continuous line from b through a to c on both
// drawings. Cells is documented as a sketch for exactly this reason; this
// test proves Canvas.Edges — the authoritative table — never makes the same
// mistake, on the exact pair that demonstrates the collision is real rather
// than theoretical.
func TestCanvasEdgesAreAuthoritativeEvenWhenCellsCollide(t *testing.T) {
	star := Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}, {ID: "c"}},
		Edges: []Edge{
			{From: "a", To: "b"}, {From: "b", To: "a"},
			{From: "a", To: "c"}, {From: "c", To: "a"},
		},
	}
	chain := Input{
		Agents: []Agent{{ID: "a"}, {ID: "b"}, {ID: "c"}},
		Edges: []Edge{
			{From: "a", To: "b"}, {From: "b", To: "a"},
			{From: "b", To: "c"}, {From: "c", To: "b"},
		},
	}

	ls, err := Layout(star)
	if err != nil {
		t.Fatal(err)
	}
	lc, err := Layout(chain)
	if err != nil {
		t.Fatal(err)
	}
	cs := Terminal(ls)
	cc := Terminal(lc)

	if cs.String() != cc.String() {
		t.Fatalf("this test's whole premise is that these two topologies draw the same Cells; "+
			"they no longer do (which is fine on its own, but means this test needs a new repro "+
			"to keep demonstrating the collision):\n--- star ---\n%s\n--- chain ---\n%s",
			cs.String(), cc.String())
	}

	hasEdge := func(edges []TerminalEdge, from, to AgentID) bool {
		for _, e := range edges {
			if e.From == agentNode(from) && e.To == agentNode(to) {
				return true
			}
		}
		return false
	}

	if !hasEdge(cs.Edges, "b", "a") || !hasEdge(cs.Edges, "a", "c") || !hasEdge(cs.Edges, "c", "a") {
		t.Errorf("star's Canvas.Edges is missing a real edge: %+v", cs.Edges)
	}
	if hasEdge(cs.Edges, "b", "c") || hasEdge(cs.Edges, "c", "b") {
		t.Errorf("star's Canvas.Edges claims a b-c edge that was never declared: %+v", cs.Edges)
	}

	if !hasEdge(cc.Edges, "b", "c") || !hasEdge(cc.Edges, "c", "b") {
		t.Errorf("chain's Canvas.Edges is missing a real edge: %+v", cc.Edges)
	}
	if hasEdge(cc.Edges, "a", "c") || hasEdge(cc.Edges, "c", "a") {
		t.Errorf("chain's Canvas.Edges claims an a-c edge that was never declared: %+v", cc.Edges)
	}
}

// TestTerminalDoesNotPanicOnZeroWidthHeight is a hand-built Placement whose
// Width and Height were simply never set — the way a Placement built by a
// test, or by some future caller that assembled one without going through
// Layout, could easily arrive. No Placement Layout itself returns can
// trigger this (Width/Height always agree with Nodes there), but Placement's
// fields are exported and nothing stopped Terminal from trusting them
// literally instead of the positions actually in Nodes.
func TestTerminalDoesNotPanicOnZeroWidthHeight(t *testing.T) {
	p := Placement{Nodes: []PlacedNode{{Node: agentNode("solo"), Pos: Point{0, 0}}}}
	c := Terminal(p)
	if len(c.Cells) == 0 || len(c.Cells[0]) == 0 {
		t.Fatal("expected a non-empty canvas despite Width == Height == 0")
	}
	if c.Cells[0][0] != '●' {
		t.Errorf("expected the node's glyph at (0,0), got %q", c.Cells[0][0])
	}
}

// TestTerminalDoesNotPanicOnNodePositionOutsideWidthHeight is the second
// half of the same finding: a hand-built Placement whose Width/Height
// understate where its Nodes actually are.
func TestTerminalDoesNotPanicOnNodePositionOutsideWidthHeight(t *testing.T) {
	p := Placement{
		Nodes: []PlacedNode{
			{Node: agentNode("a"), Pos: Point{0, 0}},
			{Node: agentNode("b"), Pos: Point{2, 3}},
		},
		// Deliberately too small for b's position at (2, 3).
		Width: 1, Height: 1,
	}
	c := Terminal(p)
	row, col := 3*rowStep, 2*colStep
	if row >= len(c.Cells) || col >= len(c.Cells[row]) {
		t.Fatalf("canvas is too small for b's actual position: %d rows x %d cols, need row %d col %d",
			len(c.Cells), len(c.Cells[0]), row, col)
	}
	if c.Cells[row][col] != '●' {
		t.Errorf("expected b's glyph at (%d,%d) despite Width/Height claiming otherwise, got %q",
			row, col, c.Cells[row][col])
	}
}
