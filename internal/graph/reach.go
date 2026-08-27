package graph

// Closure is the transitive closure of every path a message — or a
// compromised agent's output — could actually travel: a declared Edge
// directly, or a StoreKey resource one agent writes and another reads,
// chained as far as either kind of hop goes. See the package doc comment for
// why only StoreKey resources feed this and Domain/Secret ones do not.
type Closure struct {
	// Agents is the sorted row/column order Hops is indexed by.
	Agents []AgentID

	// Hops[i][j] is the number of hops on the shortest path from Agents[i]
	// to Agents[j]: -1 when there is none, 0 only on the diagonal (i == j),
	// which Reaches always reports false for — reaching oneself is not a
	// privilege question.
	Hops [][]int

	idx map[AgentID]int
}

// TransitiveClosure computes Closure for in. It shares in's validation with
// Layout (both call normalize), so the two never disagree about which agents
// and resources exist — the same Input given to both always describes one
// graph, not two that happen to agree today.
func TransitiveClosure(in Input) (Closure, error) {
	n, err := normalize(in)
	if err != nil {
		return Closure{}, err
	}

	agents := make([]AgentID, len(n.agents))
	for i, a := range n.agents {
		agents[i] = a.ID
	}
	idx := make(map[AgentID]int, len(agents))
	for i, id := range agents {
		idx[id] = i
	}

	// One-hop relation: every declared edge, plus a directed writer→reader
	// hop for every pair sharing a StoreKey resource.
	adj := make([][]int, len(agents))
	for _, e := range n.edges {
		i, j := idx[e.From], idx[e.To]
		adj[i] = append(adj[i], j)
	}

	writers := map[ResourceID][]AgentID{}
	readers := map[ResourceID][]AgentID{}
	for _, a := range n.access {
		if n.resIdx[a.Resource].Kind != StoreKey {
			continue
		}
		if a.Write {
			writers[a.Resource] = append(writers[a.Resource], a.Agent)
		} else {
			readers[a.Resource] = append(readers[a.Resource], a.Agent)
		}
	}
	for key, ws := range writers {
		for _, w := range ws {
			for _, r := range readers[key] {
				if w == r {
					continue
				}
				adj[idx[w]] = append(adj[idx[w]], idx[r])
			}
		}
	}

	hops := make([][]int, len(agents))
	for i := range hops {
		hops[i] = make([]int, len(agents))
		for j := range hops[i] {
			hops[i][j] = -1
		}
		hops[i][i] = 0
		bfsHops(i, adj, hops[i])
	}

	return Closure{Agents: agents, Hops: hops, idx: idx}, nil
}

// bfsHops fills dist (already sized len(adj), pre-set to -1 except dist[from]
// = 0) with the shortest hop count from from to every other node reachable
// over adj.
func bfsHops(from int, adj [][]int, dist []int) {
	queue := []int{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if dist[next] != -1 {
				continue
			}
			dist[next] = dist[cur] + 1
			queue = append(queue, next)
		}
	}
}

// Reaches reports whether from can reach to, directly or through a chain of
// edges and shared store keys. Always false when from == to, and false for
// any AgentID this Closure was not computed with.
func (c Closure) Reaches(from, to AgentID) bool {
	hops, ok := c.HopsBetween(from, to)
	return ok && hops > 0
}

// HopsBetween returns the shortest hop count from from to to, and whether
// to is reachable from from at all (including from == to, at 0 hops).
func (c Closure) HopsBetween(from, to AgentID) (hops int, reachable bool) {
	i, ok := c.idx[from]
	if !ok {
		return 0, false
	}
	j, ok := c.idx[to]
	if !ok {
		return 0, false
	}
	h := c.Hops[i][j]
	if h < 0 {
		return 0, false
	}
	return h, true
}

// ReachableFrom lists every agent from can reach, sorted, excluding from
// itself.
func (c Closure) ReachableFrom(from AgentID) []AgentID {
	i, ok := c.idx[from]
	if !ok {
		return nil
	}
	var out []AgentID
	for j, agent := range c.Agents {
		if j == i {
			continue
		}
		if c.Hops[i][j] >= 0 {
			out = append(out, agent)
		}
	}
	return out
}
