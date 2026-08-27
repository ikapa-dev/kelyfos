package graph

import (
	"cmp"
	"slices"
)

// The four total orders normalize sorts by, kept together and named for what
// they order rather than scattered inline at each call site. Every one is a
// plain lexical comparison over already-known fields — nothing here reads a
// map, so nothing here can vary between two runs of the same Input.

func sortAgents(a []Agent) {
	slices.SortFunc(a, func(x, y Agent) int {
		return cmp.Compare(x.ID, y.ID)
	})
}

func sortResources(r []Resource) {
	slices.SortFunc(r, func(x, y Resource) int {
		return cmp.Compare(x.ID, y.ID)
	})
}

func sortEdges(e []Edge) {
	slices.SortFunc(e, func(x, y Edge) int {
		if c := cmp.Compare(x.From, y.From); c != 0 {
			return c
		}
		return cmp.Compare(x.To, y.To)
	})
}

func sortAccess(a []Access) {
	slices.SortFunc(a, func(x, y Access) int {
		if c := cmp.Compare(x.Agent, y.Agent); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Resource, y.Resource); c != 0 {
			return c
		}
		return cmp.Compare(boolInt(x.Write), boolInt(y.Write))
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
