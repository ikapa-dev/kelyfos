package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/digest"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// demoTeamEvents mirrors dev/demo-team.toml's own shape closely enough to
// exercise every part of the run section against something a real boot
// would actually produce: a master with one declared egress domain and a
// bound secret, four workers with none, a star of edges from the master,
// a store rule scoping "findings/*" to write-by-worker/read-by-master, a
// runtime spawn that attaches a sixth agent with one edge to its spawner,
// and one store access on a key no rule covers at all (proving the
// team-wide-default synthesis).
func demoTeamEvents() []recorder.Event {
	var evs []recorder.Event
	add := func(e recorder.Event) { evs = append(evs, e) }

	add(recorder.Event{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"})

	agents := []recorder.EvAgent{
		{Name: "master", Sandbox: "sb-master"},
		{Name: "worker-1", Sandbox: "sb-w1", Group: "g1"},
		{Name: "worker-2", Sandbox: "sb-w2", Group: "g1"},
		{Name: "worker-3", Sandbox: "sb-w3", Group: "g1"},
		{Name: "worker-4", Sandbox: "sb-w4", Group: "g1"},
	}
	for _, a := range agents {
		add(recorder.Event{Type: recorder.TypeSessionReady, Agent: a.Name, TS: "2026-08-27T10:00:01.000Z"})
	}
	add(recorder.NewSessionPolicy("master", recorder.PolicyFields{
		VcpuCount: 1, MemMiB: 512,
		Allow: []string{"example.com"}, Ports: []int{80, 443},
		Secrets:   []recorder.EvSecret{{Name: "api-key", Host: "example.com", Path: "/v1"}},
		Workspace: "/work",
	}))
	for _, w := range []string{"worker-1", "worker-2", "worker-3", "worker-4"} {
		add(recorder.NewSessionPolicy(w, recorder.PolicyFields{VcpuCount: 1, MemMiB: 384}))
	}

	add(recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: agents,
		Edges: []string{
			"master -> worker-1", "master -> worker-2",
			"master -> worker-3", "master -> worker-4",
		},
		StoreKeys: []recorder.EvStoreKey{
			{Name: "findings/*", Read: []string{"master"}, Write: []string{"worker-1", "worker-2", "worker-3", "worker-4"}},
		},
	}))

	// The store round trip: each worker writes its own findings key (under
	// the declared rule), the master reads all four, worker-1 is denied
	// reading worker-2's key, and one access lands on a key no rule
	// mentions at all — proving the team-wide default.
	for _, w := range []string{"worker-1", "worker-2", "worker-3", "worker-4"} {
		add(recorder.Event{Type: recorder.TypeTeamStore, Agent: w, Peer: "findings/" + w,
			Kind: "put", Outcome: "delivered", Bytes: 20, TS: "2026-08-27T10:00:02.000Z"})
		add(recorder.Event{Type: recorder.TypeTeamStore, Agent: "master", Peer: "findings/" + w,
			Kind: "get", Outcome: "delivered", Bytes: 20, TS: "2026-08-27T10:00:03.000Z"})
	}
	add(recorder.Event{Type: recorder.TypeTeamStore, Agent: "worker-1", Peer: "findings/worker-2",
		Kind: "get", Outcome: "refused", Reason: "denied", TS: "2026-08-27T10:00:04.000Z"})
	add(recorder.Event{Type: recorder.TypeTeamStore, Agent: "worker-1", Peer: "scratch/notes",
		Kind: "put", Outcome: "delivered", Bytes: 5, TS: "2026-08-27T10:00:05.000Z"})

	// The deliberate edge violation: worker-1 to worker-2, no edge, refused
	// — and must never appear in the declared run map's edges.
	add(recorder.Event{Type: recorder.TypeTeamRefused, Agent: "worker-1", Peer: "worker-2",
		Kind: "send", Reason: "no_edge", TS: "2026-08-27T10:00:06.000Z"})

	// The runtime spawn: a sixth agent, attached with one edge to its
	// spawner, per docs/policy-record.md §4.2 / §3 — a session.ready +
	// session.policy pair, then the team.spawn event itself.
	add(recorder.Event{Type: recorder.TypeSessionReady, Agent: "worker-5", TS: "2026-08-27T10:00:07.000Z"})
	add(recorder.NewSessionPolicy("worker-5", recorder.PolicyFields{VcpuCount: 1, MemMiB: 256}))
	add(recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "master", Peer: "worker-5",
		Kind: "spawn", Outcome: "delivered", TS: "2026-08-27T10:00:08.000Z"})

	add(recorder.Event{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:09.000Z"})
	return evs
}

// The acceptance test's own arithmetic (P7-8's acceptance
// line 3): six agents, five edges, the store with its one declared ACL
// (demoTeamEvents keeps this deliberately down to one rule rather than the
// demo script's own two, since the second is redundant coverage for this
// package's purposes), the one allowed domain, and the refusal that
// carries no edge at all.
func TestRunMapCountsMatchTheAcceptanceArithmetic(t *testing.T) {
	d := digest.Walk(demoTeamEvents())
	sec := buildRunSection(d)

	if sec.Note != "" {
		t.Fatalf("run section could not be built: %s", sec.Note)
	}
	if sec.Map == nil {
		t.Fatal("no run map was built for a team session")
	}
	if sec.Map.AgentCount != 6 {
		t.Errorf("AgentCount = %d, want 6 (5 declared + 1 spawned)", sec.Map.AgentCount)
	}
	if sec.Map.EdgeCount != 5 {
		t.Errorf("EdgeCount = %d, want 5 (4 declared star edges + 1 spawn edge)", sec.Map.EdgeCount)
	}
	if sec.Map.DomainCount != 1 {
		t.Errorf("DomainCount = %d, want 1", sec.Map.DomainCount)
	}
	if len(sec.Agents) != 6 {
		t.Errorf("len(Agents) = %d, want 6", len(sec.Agents))
	}

	// The refusal carries no edge: worker-1 -> worker-2 must not appear
	// among the map's message edges, however many times it was attempted.
	for _, e := range sec.Map.Edges {
		if e.Kind == "message" && e.Title == "worker-1 → worker-2" {
			t.Errorf("a refused message became a declared edge: %+v", e)
		}
	}

	if sec.Store == nil {
		t.Fatal("no store panel for a team with a declared store rule")
	}
	if len(sec.Store.Rules) != 1 {
		t.Errorf("len(Store.Rules) = %d, want 1", len(sec.Store.Rules))
	}
	// scratch/notes matched no rule and must read as team-wide, not as a
	// silent omission.
	var sawUnruled bool
	for _, k := range sec.Store.Keys {
		if k.Key == "scratch/notes" {
			sawUnruled = true
			if k.Covered != "team-wide (no rule matches)" {
				t.Errorf("scratch/notes.Covered = %q, want the team-wide default", k.Covered)
			}
		}
	}
	if !sawUnruled {
		t.Error("scratch/notes never appears in the store panel's observed keys")
	}
}

// The declared edges only run master -> worker-N, one direction; nothing in
// demoTeamEvents declares an edge back. But worker-1 must still reach
// master in the matrix, over the writer -> reader hop TransitiveClosure
// derives from the shared findings/* store key (worker-1 writes its own
// key, master reads it) — exactly the "quieter, second path" internal/graph's
// own package doc names, which the declared edge list alone would miss.
func TestReachMatrixCountsStoreKeyHops(t *testing.T) {
	d := digest.Walk(demoTeamEvents())
	sec := buildRunSection(d)
	if sec.Reach == nil {
		t.Fatal("no reach matrix for a six-agent team")
	}
	idx := map[string]int{}
	for i, a := range sec.Reach.Agents {
		idx[a] = i
	}
	cell := func(from, to string) ReachCell {
		return sec.Reach.Rows[idx[from]].Cells[idx[to]]
	}

	// demoTeamEvents' only declared edges run master -> worker-N, one
	// direction; nothing declares worker-1 -> master. So this reach can
	// only be the store-key hop the fixture's own doc comment names
	// (worker-1 writes findings/worker-1, master reads it) — a single,
	// direct writer -> reader hop, which is exactly what this test's own
	// name claims to check and a bare Reaches assertion does not: a
	// two-hop path through some other node would also satisfy Reaches.
	if c := cell("worker-1", "master"); !c.Reaches || c.Hops != 1 {
		t.Errorf("worker-1 -> master = %+v, want a 1-hop reach via the findings/worker-1 store key "+
			"(no declared edge runs this direction at all)", c)
	}
	if got := cell("master", "master"); !got.Self {
		t.Error("the diagonal is not marked Self")
	}
}

// A store key touched under no declared rule at all is team-wide by
// default (internal/team/store.go) — every writer reaches every reader,
// which for an unruled key is the whole team. This is a fully-mixed team
// fixture with two genuinely disjoint agents deliberately kept apart from
// it: neither a declared edge nor any store rule connects them, and
// neither shares a domain or a secret, so the matrix must show no reach at
// all between them, not even a co-tenancy signal.
func TestReachMatrixDoesNotOverConnectDisjointAgents(t *testing.T) {
	events := []recorder.Event{
		recorder.NewTeamTopology(recorder.TopologyFields{
			Agents: []recorder.EvAgent{{Name: "alice"}, {Name: "bob"}},
			StoreKeys: []recorder.EvStoreKey{
				{Name: "alice-only", Read: []string{"alice"}, Write: []string{"alice"}},
			},
		}),
		{Type: recorder.TypeTeamStore, Agent: "alice", Peer: "alice-only",
			Kind: "put", Outcome: "delivered", Bytes: 3},
	}
	d := digest.Walk(events)
	sec := buildRunSection(d)
	if sec.Reach == nil {
		t.Fatal("no reach matrix for a two-agent team")
	}
	idx := map[string]int{}
	for i, a := range sec.Reach.Agents {
		idx[a] = i
	}
	c := sec.Reach.Rows[idx["alice"]].Cells[idx["bob"]]
	if c.Reaches || c.CoTenant {
		t.Errorf("alice and bob share nothing declared, got %+v", c)
	}
}

// An unruled store key is the one case this file must not understate: once
// any agent is seen touching it, every team member is a synthesized
// reader and writer of it (the team-wide default), so any two agents in a
// team that ever wrote to an unruled key must reach each other through it
// — the exact property collectStoreAccess's own doc comment names as the
// direction this view must never be wrong in.
func TestUnruledStoreKeyConnectsTheWholeTeam(t *testing.T) {
	d := digest.Walk(demoTeamEvents())
	sec := buildRunSection(d)
	idx := map[string]int{}
	for i, a := range sec.Reach.Agents {
		idx[a] = i
	}
	// scratch/notes (demoTeamEvents) has no declared rule at all — worker-2
	// and worker-3 never touched it themselves, but the team-wide default
	// still connects every pair through whoever did.
	c := sec.Reach.Rows[idx["worker-2"]].Cells[idx["worker-3"]]
	if !c.Reaches || c.Hops != 1 {
		t.Errorf("worker-2/worker-3 = %+v, want a 1-hop reach via the unruled scratch/notes key", c)
	}
}

// A non-team, single-machine session gets exactly one agent sheet — its
// own declared policy — and no map, matrix or store panel: those three are
// meaningless for a lone machine's own record.
func TestSingleMachineGetsOneSheetAndNoMap(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"},
		recorder.NewSessionPolicy("", recorder.PolicyFields{VcpuCount: 2, MemMiB: 1024, Allow: []string{"api.example.com"}}),
		{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:01.000Z"},
	}
	d := digest.Walk(events)
	sec := buildRunSection(d)
	if sec.Map != nil || sec.Reach != nil || sec.Store != nil {
		t.Errorf("a single machine grew a map/matrix/store panel: %+v", sec)
	}
	if len(sec.Agents) != 1 || !sec.Agents[0].HasPolicy || sec.Agents[0].MemMiB != 1024 {
		t.Fatalf("Agents = %+v, want exactly one sheet with MemMiB=1024", sec.Agents)
	}
}

// A session with no session.policy and no team.topology at all — the
// common case before P7-2/P7-3, or a chain that ended before either landed
// — renders no run section whatsoever, and the report must say nothing
// changed for it.
func TestNoPolicyOrTopologyMeansNoRunSection(t *testing.T) {
	html := render(t, []recorder.Event{ev(recorder.TypeCommandStart, "")})
	if strings.Contains(html, "<h2>Run</h2>") {
		t.Error("a session with no session.policy/team.topology grew a Run section")
	}
}

// The full render, end to end: the run map's SVG, the agent sheets, the
// reach matrix and the store panel are all present in the rendered page,
// and — the acceptance test's own phrasing — every count is checkable out
// of the HTML rather than eyeballed.
func TestFullReportRendersTheRunSection(t *testing.T) {
	html := render(t, demoTeamEvents())
	for _, want := range []string{
		"<h2>Run</h2>", "role=\"img\"", "<title id=\"runmap-title\">", "<desc id=\"runmap-desc\">",
		"Agent sheets", "Reach matrix", "worker-5", "spawned by master",
		"example.com", "api-key", "findings/*",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the rendered report is missing %q", want)
		}
	}
	if !strings.Contains(html, `Content-Security-Policy`) {
		t.Error("the report has no CSP meta tag")
	}
}

// Review finding 4: a fork-template Group is a content hash
// ("c049e692d3c51b083a1e37d02311de50", 32 characters) — printed in full
// beside an agent's name at 10px monospace on this map's 120px column
// pitch, adjacent agents' labels visually overlap in the real export.
// short() (report.go, already used for hashes elsewhere in this package)
// is what buildRunMap is supposed to apply; this pins that it actually
// does, on the node MapNode.Sub carries rather than on rendered pixels
// this package cannot measure.
func TestAgentGroupLabelIsShortenedOnTheMap(t *testing.T) {
	const longGroup = "c049e692d3c51b083a1e37d02311de50"
	events := []recorder.Event{
		recorder.NewTeamTopology(recorder.TopologyFields{
			Agents: []recorder.EvAgent{
				{Name: "master"},
				{Name: "worker-1", Group: longGroup},
			},
			Edges: []string{"master -> worker-1"},
		}),
	}
	d := digest.Walk(events)
	sec := buildRunSection(d)
	if sec.Map == nil {
		t.Fatal("no run map")
	}
	var found bool
	for _, n := range sec.Map.Nodes {
		if n.Label != "worker-1" {
			continue
		}
		found = true
		if n.Sub != short(longGroup) {
			t.Errorf("Sub = %q, want short(longGroup) = %q", n.Sub, short(longGroup))
		}
		if n.Sub == longGroup {
			t.Error("Sub carries the full, unshortened fork-template hash")
		}
	}
	if !found {
		t.Fatal("worker-1 never appears as a node on the map")
	}
}

// Review finding 7: a store key list past digest.MaxDistinctKeys must not
// silently understate what the map and the reach matrix draw resources
// for — Digest.StoreTruncated already exists (the store panel's own table
// already says so); buildRunSection is supposed to propagate the same
// signal into RunSection.Note, which the map and matrix render above.
func TestStoreTruncationIsPropagatedToTheRunNote(t *testing.T) {
	events := []recorder.Event{
		recorder.NewTeamTopology(recorder.TopologyFields{
			Agents: []recorder.EvAgent{{Name: "master"}, {Name: "worker-1"}},
		}),
	}
	for i := 0; i < digest.MaxDistinctKeys+1; i++ {
		events = append(events, recorder.Event{
			Type: recorder.TypeTeamStore, Agent: "master",
			Peer: fmt.Sprintf("key-%d", i), Kind: "put", Outcome: "delivered", Bytes: 1,
		})
	}
	d := digest.Walk(events)
	if !d.StoreTruncated {
		t.Fatal("the fixture did not actually trigger Digest.StoreTruncated — test setup is wrong")
	}
	sec := buildRunSection(d)
	if sec.Note == "" {
		t.Error("Digest.StoreTruncated is true but RunSection.Note says nothing about it")
	}
	if !strings.Contains(sec.Note, "MaxDistinctKeys") {
		t.Errorf("Note = %q, want it to name the truncation explicitly", sec.Note)
	}
}

// Review finding 8: team.topology is written once, at the very end of
// team boot, after every agent's own session.ready/session.policy pair —
// so a chain cut short before that last write, or simply malformed, can
// carry real per-agent policies with no topology event to hang them off
// of. buildAgentSheets must not silently drop that policy data just
// because there is no map to draw for it.
func TestAgentSheetsSurviveAMissingTopology(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeSessionReady, Agent: "master", TS: "2026-08-27T10:00:00.000Z"},
		recorder.NewSessionPolicy("master", recorder.PolicyFields{VcpuCount: 1, MemMiB: 512}),
		{Type: recorder.TypeSessionReady, Agent: "worker-1", TS: "2026-08-27T10:00:01.000Z"},
		recorder.NewSessionPolicy("worker-1", recorder.PolicyFields{VcpuCount: 1, MemMiB: 256}),
	}
	d := digest.Walk(events)
	if d.Topology != nil {
		t.Fatal("test setup is wrong: this fixture must not carry a team.topology event")
	}
	sheets := buildAgentSheets(d)
	if len(sheets) != 2 {
		t.Fatalf("len(sheets) = %d, want 2 — a missing team.topology must not drop real per-agent policy data", len(sheets))
	}
	byName := map[string]AgentSheetView{}
	for _, s := range sheets {
		byName[s.Name] = s
	}
	if s := byName["master"]; !s.HasPolicy || s.MemMiB != 512 {
		t.Errorf("master's sheet = %+v, want HasPolicy with MemMiB=512", s)
	}
	if s := byName["worker-1"]; !s.HasPolicy || s.MemMiB != 256 {
		t.Errorf("worker-1's sheet = %+v, want HasPolicy with MemMiB=256", s)
	}
}
