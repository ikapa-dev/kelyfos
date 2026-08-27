package graph

import "strings"

// Grid spacing, in rune cells, between two adjacent grid columns/rows. 4 and
// 2 leave enough room for a straight run's line glyphs and a corner without
// the canvas outrunning what fits beside a table of node names.
const (
	colStep = 4
	rowStep = 2
)

// TerminalNode is one node's entry in a Canvas's legend: its identity and
// where its glyph landed on the canvas, since the canvas itself draws a
// category glyph and never a name — a node's name is not bounded in length
// (an agent name may be up to 64 characters, docs/teams.md §1.4) and cannot
// be made to fit one cell for an arbitrary team, so identity is read from
// this table instead.
type TerminalNode struct {
	Node         NodeID
	Group        string
	ResourceKind ResourceKind
	Row, Col     int
}

// TerminalEdge is one edge's identity, independent of anything Cells drew
// for it. See Canvas's doc comment for why this exists and why Cells alone
// is never enough to read a topology off of.
type TerminalEdge struct {
	From, To NodeID
	Kind     EdgeKind
}

// Canvas is a rune grid a terminal can print directly, plus the two tables
// that say what it actually means: Legend for node identity, Edges for which
// nodes actually connect.
//
// Cells is a sketch, not a source of truth, for the same reason a node's own
// name does not fit on it: two routed edges can bend through the same grid
// cell — the routing in layout.go picks a corner from a source's column and
// a target's row (or vice versa), and on a real team that point is often
// another node's own position — so a line that looks continuous on Cells can
// be two unrelated edges whose corners happened to land on a third node, and
// a corner landing exactly on a node's cell is drawn over by that node's own
// glyph and vanishes. Read literally, Cells can show a star topology as a
// connected chain: two workers with no edge between them at all, joined on
// the page by a hub's line passing behind a third worker's glyph. This is
// not a hypothetical — testdata/golden/star_with_resources.txt's own worker
// row draws exactly that, and TestCanvasEdgesAreAuthoritativeEvenWhenCellsCollide
// exists to keep it that way on purpose rather than by accident.
//
// Edges is what actually connects to what, straight from the Placement's own
// RoutedEdges and unaffected by anything Cells drew or failed to draw — a
// renderer that wants to say what the topology is, rather than what it looks
// like it might be, reads this table and not the picture.
type Canvas struct {
	Cells  [][]rune
	Legend []TerminalNode
	Edges  []TerminalEdge
}

// String renders the canvas as newline-joined rows, each with trailing
// spaces trimmed so a diff between two canvases shows only what actually
// differs.
func (c Canvas) String() string {
	lines := make([]string, len(c.Cells))
	for i, row := range c.Cells {
		lines[i] = strings.TrimRight(string(row), " ")
	}
	return strings.Join(lines, "\n")
}

func glyphFor(n PlacedNode) rune {
	if n.Node.Kind == NodeAgent {
		return '●'
	}
	switch n.ResourceKind {
	case Domain:
		return '◆'
	case StoreKey:
		return '■'
	case Secret:
		return '▲'
	default:
		return '□'
	}
}

// Terminal renders l as a rune canvas: the one backend of the layout that
// draws with characters, the way `kelyfos team graph` and `watch` need. The
// other is SVG (svg.go); both draw the exact same Placement, so a diagram in
// the terminal and one in an exported report never disagree about a topology
// their common caller only computed once.
//
// The canvas is sized from the actual maximum node and path position in l,
// never from l.Width/l.Height directly. Every Placement Layout returns has
// those fields agree with its Nodes and Edges, so this only matters for a
// Placement built by hand — Placement's fields are exported and cornerGlyph
// already anticipates hand-built ones (as tests do) — where a Width or
// Height smaller than what l.Nodes actually uses would otherwise panic
// rather than draw a wider canvas than claimed.
func Terminal(l Placement) Canvas {
	if len(l.Nodes) == 0 {
		return Canvas{}
	}

	maxX, maxY := 0, 0
	for _, node := range l.Nodes {
		if node.Pos.X > maxX {
			maxX = node.Pos.X
		}
		if node.Pos.Y > maxY {
			maxY = node.Pos.Y
		}
	}
	for _, e := range l.Edges {
		for _, p := range e.Path {
			if p.X > maxX {
				maxX = p.X
			}
			if p.Y > maxY {
				maxY = p.Y
			}
		}
	}

	rows := maxY*rowStep + 1
	cols := maxX*colStep + 1
	cells := make([][]rune, rows)
	for i := range cells {
		cells[i] = make([]rune, cols)
		for j := range cells[i] {
			cells[i][j] = ' '
		}
	}

	edges := make([]TerminalEdge, 0, len(l.Edges))
	for _, e := range l.Edges {
		drawPath(cells, e.Path)
		edges = append(edges, TerminalEdge{From: e.From, To: e.To, Kind: e.Kind})
	}

	legend := make([]TerminalNode, 0, len(l.Nodes))
	for _, node := range l.Nodes {
		r, c := node.Pos.Y*rowStep, node.Pos.X*colStep
		cells[r][c] = glyphFor(node)
		legend = append(legend, TerminalNode{
			Node:         node.Node,
			Group:        node.Group,
			ResourceKind: node.ResourceKind,
			Row:          r,
			Col:          c,
		})
	}

	return Canvas{Cells: cells, Legend: legend, Edges: edges}
}

// drawPath rasterizes one routed, axis-aligned path (2 or 3 grid points) onto
// cells, in scaled rune coordinates. Every segment is drawn before any
// corner glyph is placed, so a corner is never overwritten by the straight
// glyph of the segment either side of it.
func drawPath(cells [][]rune, path []Point) {
	for i := 0; i+1 < len(path); i++ {
		drawSegment(cells, path[i], path[i+1])
	}
	for i := 1; i+1 < len(path); i++ {
		cells[path[i].Y*rowStep][path[i].X*colStep] = cornerGlyph(path[i-1], path[i], path[i+1])
	}
}

func drawSegment(cells [][]rune, a, b Point) {
	ar, ac := a.Y*rowStep, a.X*colStep
	br, bc := b.Y*rowStep, b.X*colStep
	switch {
	case ar == br:
		lo, hi := ac, bc
		if lo > hi {
			lo, hi = hi, lo
		}
		for c := lo; c <= hi; c++ {
			if cells[ar][c] == ' ' {
				cells[ar][c] = '─'
			}
		}
	case ac == bc:
		lo, hi := ar, br
		if lo > hi {
			lo, hi = hi, lo
		}
		for r := lo; r <= hi; r++ {
			if cells[r][ac] == ' ' {
				cells[r][ac] = '│'
			}
		}
	}
	// Every path Layout produces is axis-aligned (route never returns a
	// diagonal segment); a segment that is neither is not drawable and is
	// left untouched rather than guessed at.
}

// cornerGlyph picks the box-drawing character for the bend at b, from the
// compass direction of the arm reaching back to prev and the arm reaching
// forward to next. Every path Layout produces bends at most once, with prev
// and next on perpendicular axes, so exactly one of the four cases below
// always applies to output from route(); the default exists for a Layout
// built by hand (as tests do) rather than by Layout itself.
func cornerGlyph(prev, b, next Point) rune {
	toPrev := direction(b, prev)
	toNext := direction(b, next)
	switch {
	case arms(toPrev, toNext, 'N', 'E'):
		return '└'
	case arms(toPrev, toNext, 'N', 'W'):
		return '┘'
	case arms(toPrev, toNext, 'S', 'E'):
		return '┌'
	case arms(toPrev, toNext, 'S', 'W'):
		return '┐'
	default:
		if toPrev == 'N' || toPrev == 'S' {
			return '│'
		}
		return '─'
	}
}

// arms reports whether the unordered pair {a, b} equals the unordered pair
// {x, y}.
func arms(a, b, x, y byte) bool {
	return (a == x && b == y) || (a == y && b == x)
}

// direction reports the compass direction of b relative to a — the
// direction travel moves in, going from a to b.
func direction(a, b Point) byte {
	switch {
	case b.Y > a.Y:
		return 'S'
	case b.Y < a.Y:
		return 'N'
	case b.X > a.X:
		return 'E'
	default:
		return 'W'
	}
}
