package graph

import "slices"

// NodeKind distinguishes the two kinds of node a Layout places.
type NodeKind uint8

const (
	NodeAgent NodeKind = iota
	NodeResource
)

// NodeID identifies one placed node unambiguously. An agent and a resource
// are different namespaces — a store key could in principle share a literal
// string with an agent name — so identity here is (Kind, ID), never ID alone.
type NodeID struct {
	Kind NodeKind
	ID   string
}

func agentNode(id AgentID) NodeID       { return NodeID{Kind: NodeAgent, ID: string(id)} }
func resourceNode(id ResourceID) NodeID { return NodeID{Kind: NodeResource, ID: string(id)} }

// Point is a placement in abstract grid units — not pixels, not runes.
// Adjacent integers mean "next column" or "next row"; a backend decides what
// that costs in its own coordinate space.
type Point struct{ X, Y int }

// PlacedNode is one node after layout: its identity, position, and the
// context a renderer needs without walking back to the Input.
type PlacedNode struct {
	Node NodeID
	Pos  Point

	// Group is set only when Node.Kind == NodeAgent, from the matching
	// Agent.Group.
	Group string
	// ResourceKind is set only when Node.Kind == NodeResource, from the
	// matching Resource.Kind.
	ResourceKind ResourceKind
}

// EdgeKind says what a RoutedEdge represents. An agent-agent edge and an
// agent's touch on a resource are drawn the same way — a routed polyline —
// but they answer different questions for a reader deciding what a
// compromise of one node puts at risk (see the package doc comment).
type EdgeKind uint8

const (
	EdgeMessage EdgeKind = iota // a declared, directed team.edge
	EdgeRead                    // an agent's read access to a resource
	EdgeWrite                   // an agent's write access to a resource
)

// RoutedEdge is one edge after routing: its endpoints and the axis-aligned
// polyline between them. Path always starts at From's Pos and ends at To's
// Pos; it has either two points (a straight run) or three (one bend), never
// more — Layout only ever needs one corner to connect a grid of rows and
// columns.
type RoutedEdge struct {
	From, To NodeID
	Kind     EdgeKind
	Path     []Point
}

// Placement is the placed, routed result of Layout: everything a terminal or
// an SVG backend needs and nothing either backend gets to decide differently.
type Placement struct {
	Nodes []PlacedNode
	Edges []RoutedEdge

	// Width and Height are the grid's extent: every Pos.X < Width and every
	// Pos.Y < Height. Both are 0 when there are no nodes at all.
	Width, Height int
}

// nodeGap separates one connected component of agents from the next along X,
// and separates the agent rows from the resource rows along Y, so two
// components (or an agent row and a resource row) are never drawn touching.
const nodeGap = 1

// Layout places every agent and every resource in Input on a deterministic
// grid, and routes every Edge and every Access between the nodes it
// connects.
//
// Placement, in order:
//
//  1. Agents are grouped into connected components using Edges as an
//     undirected graph (an Access to a shared resource does not connect two
//     agents for placement purposes — only a declared edge does; see the
//     package doc comment for why Access is drawn but not used to compute
//     reachability structure here).
//  2. Components are laid out left to right, in ascending order of their
//     smallest agent ID — which is also the order they are discovered in,
//     since agents are visited in ID order and a component's smallest member
//     is always the first of its members reached.
//  3. Within a component, the agent with the most distinct neighbours (ties
//     broken by the smallest ID) is the root, at row 0. Every other agent's
//     row is its shortest hop distance from the root over the undirected
//     edge graph — a star's hub sits above every spoke, a chain lays out top
//     to bottom.
//  4. Within a row, agents are ordered by ID, column 0 upward.
//  5. Resources are placed below every agent row, one row per Kind that is
//     actually present (Domain, then StoreKey, then Secret, skipping any
//     Kind with nothing to place), each row ordered by ID.
//
// Routing: an edge between two nodes on the same row or the same column is a
// straight line; otherwise it bends once, moving along the source's column
// to the target's row and then along that row to the target — the shape an
// org chart draws, which is also the shape both backends can rasterize
// without guessing.
func Layout(in Input) (Placement, error) {
	n, err := normalize(in)
	if err != nil {
		return Placement{}, err
	}

	pos := make(map[NodeID]Point, len(n.agents)+len(n.resources))
	var nodes []PlacedNode

	maxAgentRow := -1
	xOffset := 0
	for _, comp := range components(n) {
		root := hub(comp, n)
		rows := bfsRows(comp, root, n)

		byRow := map[int][]AgentID{}
		maxRow := 0
		for agent, row := range rows {
			byRow[row] = append(byRow[row], agent)
			if row > maxRow {
				maxRow = row
			}
		}
		width := 0
		for row := 0; row <= maxRow; row++ {
			members := byRow[row]
			sortAgentIDs(members)
			if len(members) > width {
				width = len(members)
			}
			for col, id := range members {
				p := Point{X: xOffset + col, Y: row}
				pos[agentNode(id)] = p
				nodes = append(nodes, PlacedNode{
					Node:  agentNode(id),
					Pos:   p,
					Group: n.agents[n.agentIdx[id]].Group,
				})
			}
		}
		if maxRow > maxAgentRow {
			maxAgentRow = maxRow
		}
		xOffset += width + nodeGap
	}

	resourceStartRow := 0
	if maxAgentRow >= 0 {
		resourceStartRow = maxAgentRow + 1 + nodeGap
	}
	row := resourceStartRow
	for _, kind := range []ResourceKind{Domain, StoreKey, Secret} {
		var col int
		var placedAny bool
		for _, r := range n.resources {
			if r.Kind != kind {
				continue
			}
			p := Point{X: col, Y: row}
			pos[resourceNode(r.ID)] = p
			nodes = append(nodes, PlacedNode{
				Node:         resourceNode(r.ID),
				Pos:          p,
				ResourceKind: r.Kind,
			})
			col++
			placedAny = true
		}
		if placedAny {
			row++
		}
	}

	var edges []RoutedEdge
	for _, e := range n.edges {
		edges = append(edges, RoutedEdge{
			From: agentNode(e.From),
			To:   agentNode(e.To),
			Kind: EdgeMessage,
			Path: route(pos[agentNode(e.From)], pos[agentNode(e.To)]),
		})
	}
	for _, a := range n.access {
		kind := EdgeRead
		if a.Write {
			kind = EdgeWrite
		}
		edges = append(edges, RoutedEdge{
			From: agentNode(a.Agent),
			To:   resourceNode(a.Resource),
			Kind: kind,
			Path: route(pos[agentNode(a.Agent)], pos[resourceNode(a.Resource)]),
		})
	}

	width, height := 0, 0
	for _, p := range nodes {
		if p.Pos.X+1 > width {
			width = p.Pos.X + 1
		}
		if p.Pos.Y+1 > height {
			height = p.Pos.Y + 1
		}
	}

	return Placement{Nodes: nodes, Edges: edges, Width: width, Height: height}, nil
}

// route returns the axis-aligned polyline from a to b: a straight two-point
// line when they share a row or a column, otherwise a three-point path that
// bends once at (a.X, b.Y).
func route(a, b Point) []Point {
	if a.X == b.X || a.Y == b.Y {
		return []Point{a, b}
	}
	return []Point{a, {X: a.X, Y: b.Y}, b}
}

// components partitions n's agents into connected components over the
// undirected view of n.edges, in ascending order of each component's
// smallest agent ID. An agent with no edges at all is its own component.
func components(n normalized) [][]AgentID {
	adj := undirected(n)
	visited := make(map[AgentID]bool, len(n.agents))
	var comps [][]AgentID
	for _, a := range n.agents {
		if visited[a.ID] {
			continue
		}
		var comp []AgentID
		queue := []AgentID{a.ID}
		visited[a.ID] = true
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			comp = append(comp, cur)
			for _, next := range adj[cur] {
				if !visited[next] {
					visited[next] = true
					queue = append(queue, next)
				}
			}
		}
		sortAgentIDs(comp)
		comps = append(comps, comp)
	}
	return comps
}

// undirected builds, for every agent with at least one edge, the sorted,
// deduplicated set of agents it shares an edge with in either direction.
func undirected(n normalized) map[AgentID][]AgentID {
	set := make(map[AgentID]map[AgentID]bool, len(n.agents))
	add := func(a, b AgentID) {
		if set[a] == nil {
			set[a] = map[AgentID]bool{}
		}
		set[a][b] = true
	}
	for _, e := range n.edges {
		add(e.From, e.To)
		add(e.To, e.From)
	}
	out := make(map[AgentID][]AgentID, len(set))
	for a, neighbours := range set {
		var list []AgentID
		for b := range neighbours {
			list = append(list, b)
		}
		sortAgentIDs(list)
		out[a] = list
	}
	return out
}

// hub picks the deterministic root of a component: the agent with the most
// distinct neighbours, ties broken by the smallest ID.
func hub(comp []AgentID, n normalized) AgentID {
	adj := undirected(n)
	best := comp[0]
	bestDegree := -1
	for _, a := range comp {
		degree := len(adj[a])
		if degree > bestDegree || (degree == bestDegree && a < best) {
			best = a
			bestDegree = degree
		}
	}
	return best
}

// bfsRows assigns every agent in comp its shortest hop distance from root
// over the undirected edge graph.
func bfsRows(comp []AgentID, root AgentID, n normalized) map[AgentID]int {
	adj := undirected(n)
	rows := map[AgentID]int{root: 0}
	queue := []AgentID{root}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if _, seen := rows[next]; seen {
				continue
			}
			rows[next] = rows[cur] + 1
			queue = append(queue, next)
		}
	}
	return rows
}

func sortAgentIDs(a []AgentID) { slices.Sort(a) }
