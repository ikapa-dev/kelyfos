package graph

import (
	"strings"
	"testing"
)

func TestTerminalEmptyLayout(t *testing.T) {
	c := Terminal(Placement{})
	if len(c.Cells) != 0 || len(c.Legend) != 0 {
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

// TestDrawSegmentNeverOverwritesAGlyph guards the invariant drawPath relies
// on: when two edges cross the same cell, the first glyph drawn survives
// (drawSegment only writes into a blank cell), so a crossing never silently
// turns into something that looks like a third, nonexistent connection.
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
