package graph

import (
	"fmt"
	"reflect"
	"testing"
)

// The fuzz target for P7-6. Layout and TransitiveClosure are pure functions
// over a small, closed Input — no I/O, no guest, nothing an attacker
// controls beyond the shape of the graph itself — so what is worth fuzzing
// is not injection, it is the two properties the task exists to guarantee:
// the functions never panic on any graph shape, including a hostile one full
// of duplicate IDs, dangling references and cycles, and they are
// deterministic — the same Input, normalized twice, must produce the exact
// same answer both times, because a layout that moves between two runs of
// the same team is a diff nobody can read.
//
// Bounded pools rather than raw fuzz bytes as IDs: agent and resource names
// come from a small fixed set ("a0".."a7", "r0".."r7") so duplicate IDs and
// dangling references — the two cases normalize is specifically written to
// catch — occur naturally and often, instead of needing a fuzz corpus lucky
// enough to collide two arbitrary byte strings.

const (
	fuzzMaxAgents    = 8
	fuzzMaxResources = 8
	fuzzMaxEdges     = 16
	fuzzMaxAccess    = 16
)

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) next() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func fuzzInput(data []byte) Input {
	r := &byteReader{data: data}

	var in Input

	numAgents := int(r.next()) % (fuzzMaxAgents + 1)
	for i := 0; i < numAgents; i++ {
		a := Agent{ID: AgentID(fmt.Sprintf("a%d", int(r.next())%fuzzMaxAgents))}
		if r.next()%2 == 0 {
			a.Group = fmt.Sprintf("g%d", int(r.next())%4)
		}
		in.Agents = append(in.Agents, a)
	}

	numResources := int(r.next()) % (fuzzMaxResources + 1)
	for i := 0; i < numResources; i++ {
		in.Resources = append(in.Resources, Resource{
			ID:   ResourceID(fmt.Sprintf("r%d", int(r.next())%fuzzMaxResources)),
			Kind: ResourceKind(int(r.next()) % 3),
		})
	}

	numEdges := int(r.next()) % (fuzzMaxEdges + 1)
	for i := 0; i < numEdges; i++ {
		in.Edges = append(in.Edges, Edge{
			From: AgentID(fmt.Sprintf("a%d", int(r.next())%fuzzMaxAgents)),
			To:   AgentID(fmt.Sprintf("a%d", int(r.next())%fuzzMaxAgents)),
		})
	}

	numAccess := int(r.next()) % (fuzzMaxAccess + 1)
	for i := 0; i < numAccess; i++ {
		in.Access = append(in.Access, Access{
			Agent:    AgentID(fmt.Sprintf("a%d", int(r.next())%fuzzMaxAgents)),
			Resource: ResourceID(fmt.Sprintf("r%d", int(r.next())%fuzzMaxResources)),
			Write:    r.next()%2 == 0,
		})
	}

	return in
}

func FuzzLayoutNeverPanicsAndIsDeterministic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0xff})
	f.Add(make([]byte, 64)) // all zero: max agents/resources/edges/access, ID "a0"/"r0" throughout
	{
		allFF := make([]byte, 64)
		for i := range allFF {
			allFF[i] = 0xff
		}
		f.Add(allFF)
	}
	// A hand-built duplicate-agent case and a hand-built dangling-edge case,
	// so the error path is in the seed corpus rather than left to chance.
	f.Add([]byte{2, 0, 0, 0, 0})          // 2 agents, both "a0": duplicate
	f.Add([]byte{1, 0, 0, 0, 0, 1, 0, 7}) // 1 agent "a0", 1 edge a0->a7 (dangling)

	f.Fuzz(func(t *testing.T, data []byte) {
		in := fuzzInput(data)

		l1, err1 := Layout(in)
		c1, err1c := TransitiveClosure(in)

		if (err1 == nil) != (err1c == nil) {
			t.Fatalf("Layout and TransitiveClosure disagreed about whether this Input is valid: "+
				"Layout err=%v, TransitiveClosure err=%v, input=%+v", err1, err1c, in)
		}
		if err1 != nil {
			return // A refused Input has nothing further to check.
		}

		// Determinism: normalizing and computing again must be byte-for-byte
		// identical — asserted with reflect.DeepEqual directly on the
		// Placement and Closure structs, which is the level that actually
		// matters. A review finding proved the Terminal-string comparison
		// alone is not enough: rebuilding Layout's Nodes/Edges slices via
		// unordered map iteration (identical positions, nondeterministic
		// slice order) still passed every test and 2.8M fuzz execs when the
		// only check was on rendered output, because Terminal draws by
		// position and does not care what order it received things in. SVG
		// maps l.Nodes/l.Edges index-for-index, so a Placement whose slice
		// order varies between two runs is exactly the "diff nobody can
		// read" this task exists to prevent, one layer down from anything a
		// human looks at.
		l2, err2 := Layout(in)
		if err2 != nil {
			t.Fatalf("Layout succeeded once and failed on an identical second call: %v", err2)
		}
		if !reflect.DeepEqual(l1, l2) {
			t.Fatalf("Layout is not deterministic at the Placement level for input=%+v", in)
		}
		if Terminal(l1).String() != Terminal(l2).String() {
			t.Fatalf("Layout is not deterministic for input=%+v", in)
		}
		if s1, s2 := SVG(l1, DefaultSVGOptions()), SVG(l2, DefaultSVGOptions()); !reflect.DeepEqual(s1, s2) {
			t.Fatalf("SVG is not deterministic for input=%+v", in)
		}

		c2, err2c := TransitiveClosure(in)
		if err2c != nil {
			t.Fatalf("TransitiveClosure succeeded once and failed on an identical second call: %v", err2c)
		}
		if !reflect.DeepEqual(c1.Agents, c2.Agents) || !reflect.DeepEqual(c1.Hops, c2.Hops) {
			t.Fatalf("TransitiveClosure is not deterministic for input=%+v", in)
		}

		checkLayoutInvariants(t, l1)
		checkClosureInvariants(t, c1)
	})
}

func checkLayoutInvariants(t *testing.T, l Placement) {
	t.Helper()

	seen := map[NodeID]Point{}
	for _, n := range l.Nodes {
		if _, dup := seen[n.Node]; dup {
			t.Fatalf("node %v placed twice", n.Node)
		}
		seen[n.Node] = n.Pos
		if n.Pos.X < 0 || n.Pos.X >= l.Width {
			t.Fatalf("node %v X=%d outside [0,%d)", n.Node, n.Pos.X, l.Width)
		}
		if n.Pos.Y < 0 || n.Pos.Y >= l.Height {
			t.Fatalf("node %v Y=%d outside [0,%d)", n.Node, n.Pos.Y, l.Height)
		}
	}

	for _, e := range l.Edges {
		fromPos, ok := seen[e.From]
		if !ok {
			t.Fatalf("routed edge references a From node that was never placed: %+v", e)
		}
		toPos, ok := seen[e.To]
		if !ok {
			t.Fatalf("routed edge references a To node that was never placed: %+v", e)
		}
		if len(e.Path) < 2 {
			t.Fatalf("routed edge path has fewer than 2 points: %+v", e)
		}
		if e.Path[0] != fromPos {
			t.Fatalf("routed edge path does not start at From's position: %+v", e)
		}
		if e.Path[len(e.Path)-1] != toPos {
			t.Fatalf("routed edge path does not end at To's position: %+v", e)
		}
		if len(e.Path) > 3 {
			t.Fatalf("routed edge path has more than one bend: %+v", e)
		}
		for i := 0; i+1 < len(e.Path); i++ {
			a, b := e.Path[i], e.Path[i+1]
			if a.X != b.X && a.Y != b.Y {
				t.Fatalf("routed edge segment %v→%v is not axis-aligned: %+v", a, b, e)
			}
		}
	}

	// Terminal must never panic on Layout's own output, and Canvas.Edges must
	// be a faithful, order-preserving projection of l.Edges regardless of
	// whatever Cells drew (the review finding that Cells alone can be
	// ambiguous — see terminal.go's Canvas doc comment — is exactly why
	// Edges exists and must always agree with the Placement it came from).
	canvas := Terminal(l)
	if len(canvas.Edges) != len(l.Edges) {
		t.Fatalf("Canvas.Edges has %d entries for %d Placement edges", len(canvas.Edges), len(l.Edges))
	}
	for i, e := range l.Edges {
		if canvas.Edges[i] != (TerminalEdge{From: e.From, To: e.To, Kind: e.Kind}) {
			t.Fatalf("Canvas.Edges[%d] = %+v does not match Placement edge %+v", i, canvas.Edges[i], e)
		}
	}
}

func checkClosureInvariants(t *testing.T, c Closure) {
	t.Helper()

	if len(c.Hops) != len(c.Agents) {
		t.Fatalf("Hops has %d rows for %d agents", len(c.Hops), len(c.Agents))
	}
	for i, row := range c.Hops {
		if len(row) != len(c.Agents) {
			t.Fatalf("Hops row %d has %d columns for %d agents", i, len(row), len(c.Agents))
		}
		for j, h := range row {
			if i == j && h != 0 {
				t.Fatalf("Hops[%d][%d] (self) = %d, want 0", i, j, h)
			}
			if i != j && h == 0 {
				t.Fatalf("Hops[%d][%d] = 0 for a non-self pair", i, j)
			}
			if h < -1 {
				t.Fatalf("Hops[%d][%d] = %d, want >= -1", i, j, h)
			}
		}
	}
	for _, a := range c.Agents {
		if c.Reaches(a, a) {
			t.Fatalf("agent %q reaches itself, which Reaches must never report", a)
		}
		if got := c.SharedResources(a, a); got != nil {
			t.Fatalf("SharedResources(%q, %q) = %v, want nil for an agent and itself", a, a, got)
		}
	}
	for _, a := range c.Agents {
		for _, b := range c.Agents {
			ab, ba := c.SharedResources(a, b), c.SharedResources(b, a)
			if !reflect.DeepEqual(ab, ba) {
				t.Fatalf("SharedResources(%q,%q)=%v but SharedResources(%q,%q)=%v — "+
					"co-tenancy must be symmetric", a, b, ab, b, a, ba)
			}
		}
	}
}
