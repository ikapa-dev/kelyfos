package graph

// SVGPoint is one coordinate in pixel space.
type SVGPoint struct{ X, Y float64 }

// SVGNode is one placed node, scaled to pixels.
type SVGNode struct {
	Node         NodeID
	Group        string
	ResourceKind ResourceKind
	Pos          SVGPoint
}

// SVGEdge is one routed edge, scaled to pixels.
type SVGEdge struct {
	From, To NodeID
	Kind     EdgeKind
	Path     []SVGPoint
}

// SVGLayout is a Placement after SVGOptions has turned its grid units into
// pixel coordinates: the second of the two backends (Terminal is the first).
// This package emits numbers only — an SVGLayout carries no markup, no
// attribute string and nothing that needs escaping, so whatever renders it
// (P7-8's report, eventually) draws every element from data it computed
// rather than from a string this package assembled.
type SVGLayout struct {
	Nodes         []SVGNode
	Edges         []SVGEdge
	Width, Height float64
}

// SVGOptions scales a Placement's abstract grid units into pixel coordinates.
type SVGOptions struct {
	// ColStep and RowStep are the pixel distance between adjacent grid
	// columns and rows.
	ColStep, RowStep float64
	// Margin is the pixel padding added on every side, so a node drawn with
	// its own radius at grid position (0, 0) never touches the canvas edge.
	Margin float64
}

// DefaultSVGOptions returns sized, tested defaults: wide enough to fit a
// node's glyph and a short label beside it without two adjacent columns
// overlapping.
func DefaultSVGOptions() SVGOptions {
	return SVGOptions{ColStep: 120, RowStep: 80, Margin: 40}
}

func (o SVGOptions) point(p Point) SVGPoint {
	return SVGPoint{
		X: o.Margin + float64(p.X)*o.ColStep,
		Y: o.Margin + float64(p.Y)*o.RowStep,
	}
}

// SVG scales l into pixel coordinates using opt. A zero-value opt (every
// field 0) is replaced with DefaultSVGOptions before scaling, since a step
// of 0 would place every node on top of every other.
func SVG(l Placement, opt SVGOptions) SVGLayout {
	if opt == (SVGOptions{}) {
		opt = DefaultSVGOptions()
	}

	nodes := make([]SVGNode, len(l.Nodes))
	for i, n := range l.Nodes {
		nodes[i] = SVGNode{
			Node:         n.Node,
			Group:        n.Group,
			ResourceKind: n.ResourceKind,
			Pos:          opt.point(n.Pos),
		}
	}

	edges := make([]SVGEdge, len(l.Edges))
	for i, e := range l.Edges {
		path := make([]SVGPoint, len(e.Path))
		for j, p := range e.Path {
			path[j] = opt.point(p)
		}
		edges[i] = SVGEdge{From: e.From, To: e.To, Kind: e.Kind, Path: path}
	}

	width, height := 2*opt.Margin, 2*opt.Margin
	if l.Width > 0 {
		width = 2*opt.Margin + float64(l.Width-1)*opt.ColStep
	}
	if l.Height > 0 {
		height = 2*opt.Margin + float64(l.Height-1)*opt.RowStep
	}

	return SVGLayout{Nodes: nodes, Edges: edges, Width: width, Height: height}
}
