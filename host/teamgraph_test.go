package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/graph"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

func TestExpandStoreSpecsHandlesStarPrefixAndLiteral(t *testing.T) {
	agents := []string{"master", "worker-1", "worker-2"}

	if got := expandStoreSpecs([]string{"*"}, agents); strings.Join(got, ",") != "master,worker-1,worker-2" {
		t.Errorf(`"*" = %v, want every agent`, got)
	}
	if got := expandStoreSpecs([]string{"worker-*"}, agents); strings.Join(got, ",") != "worker-1,worker-2" {
		t.Errorf(`"worker-*" = %v, want just the workers`, got)
	}
	if got := expandStoreSpecs([]string{"master"}, agents); strings.Join(got, ",") != "master" {
		t.Errorf("a literal name = %v, want [master]", got)
	}
	if got := expandStoreSpecs([]string{"master", "worker-*"}, agents); strings.Join(got, ",") != "master,worker-1,worker-2" {
		t.Errorf("mixed specs = %v", got)
	}
}

// The one thing internal/graph's own package doc names as the caller's
// obligation: a store key no [[team.store.key]] rule matches is team-wide by
// default, and omitting an Access for it would understate what the team can
// touch — the one direction a reach view must never fail in.
func TestBuildGraphInputSynthesizesAccessForUnmatchedStoreKeys(t *testing.T) {
	agents := []graphAgent{{Name: "master"}, {Name: "worker-1"}}
	store := []graphStoreRule{{Name: "findings", Read: []string{"master"}, Write: []string{"worker-1"}}}

	in, err := buildGraphInput(agents, nil, store, true)
	if err != nil {
		t.Fatal(err)
	}

	var sawUnmatched bool
	for _, r := range in.Resources {
		if r.ID == unmatchedStoreKeyID {
			sawUnmatched = true
			if r.Kind != graph.StoreKey {
				t.Errorf("unmatched-key resource has Kind %v, want StoreKey", r.Kind)
			}
		}
	}
	if !sawUnmatched {
		t.Fatal("no synthetic resource for keys no rule names — a reach view built from this " +
			"Input would understate what the team can touch")
	}
	for _, agentName := range []string{"master", "worker-1"} {
		var read, write bool
		for _, a := range in.Access {
			if a.Agent == graph.AgentID(agentName) && a.Resource == unmatchedStoreKeyID {
				if a.Write {
					write = true
				} else {
					read = true
				}
			}
		}
		if !read || !write {
			t.Errorf("%s does not have both read and write access to %q: read=%v write=%v",
				agentName, unmatchedStoreKeyID, read, write)
		}
	}

	// A team with the store OFF gets no synthetic resource: there is nothing
	// declared for it to stand in for.
	off, err := buildGraphInput(agents, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range off.Resources {
		if r.ID == unmatchedStoreKeyID {
			t.Error("a team with the store off still got the synthetic unmatched-key resource")
		}
	}
}

// A store enabled with ZERO [[team.store.key]] rules is not the same as no
// store at all: per internal/team/store.go, every key is then team-wide by
// default, and a review caught buildGraphInput gating the synthetic
// resource on len(store) > 0 instead of the real, independent storeEnabled
// flag — a live 3-agent team with an empty, enabled store drew no store
// node at all. storeEnabled and store are deliberately independent
// parameters (host/teamplan.go's teamPlan draws them as two separate
// fields) so this case is representable.
func TestBuildGraphInputSynthesizesAccessForAnEnabledStoreWithZeroRules(t *testing.T) {
	agents := []graphAgent{{Name: "master"}, {Name: "worker-1"}}

	in, err := buildGraphInput(agents, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var sawUnmatched bool
	for _, r := range in.Resources {
		if r.ID == unmatchedStoreKeyID {
			sawUnmatched = true
		}
	}
	if !sawUnmatched {
		t.Fatal("an enabled store with zero rules got no store resource at all — every key is " +
			"team-wide by default here, and this view drew nothing for it")
	}
	for _, agentName := range []string{"master", "worker-1"} {
		var read, write bool
		for _, a := range in.Access {
			if a.Agent == graph.AgentID(agentName) && a.Resource == unmatchedStoreKeyID {
				if a.Write {
					write = true
				} else {
					read = true
				}
			}
		}
		if !read || !write {
			t.Errorf("%s does not have both read and write access to the open store: read=%v write=%v",
				agentName, read, write)
		}
	}
}

func TestBuildGraphInputResolvesDomainsAndSecretsPerAgent(t *testing.T) {
	agents := []graphAgent{
		{Name: "master", Allow: []string{"example.com"}, Secrets: []recorder.EvSecret{{Name: "TOK", Host: "example.com"}}},
		{Name: "worker"},
	}
	in, err := buildGraphInput(agents, []string{"master -> worker"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Edges) != 1 || in.Edges[0].From != "master" || in.Edges[0].To != "worker" {
		t.Errorf("edges = %+v", in.Edges)
	}

	var sawDomain, sawSecret bool
	for _, r := range in.Resources {
		switch {
		case r.ID == "example.com" && r.Kind == graph.Domain:
			sawDomain = true
		case r.ID == "TOK@example.com" && r.Kind == graph.Secret:
			sawSecret = true
		}
	}
	if !sawDomain {
		t.Error("no domain resource for master's allow list")
	}
	if !sawSecret {
		t.Error("no secret resource for master's bound credential")
	}
	// worker was declared with neither, and gets no access to either resource.
	for _, a := range in.Access {
		if a.Agent == "worker" {
			t.Errorf("worker has an access it was never granted: %+v", a)
		}
	}
}

func TestBuildGraphInputRefusesAMalformedEdge(t *testing.T) {
	agents := []graphAgent{{Name: "a"}, {Name: "b"}}
	if _, err := buildGraphInput(agents, []string{"a --- b"}, nil, false); err == nil {
		t.Error("an edge with no \" -> \" was accepted")
	}
}

func TestGraphAgentsFromPlanParsesSecretsAndSkipsUnparsable(t *testing.T) {
	plan := &teamPlan{agents: []plannedAgent{
		{name: "master", allow: []string{"api.github.com"}, secrets: []string{"GITHUB_TOKEN@api.github.com"}},
		{name: "broken", secrets: []string{"not-a-valid-spec"}},
	}}
	got := graphAgentsFromPlan(plan)
	if len(got) != 2 {
		t.Fatalf("got %d agents, want 2", len(got))
	}
	if len(got[0].Secrets) != 1 || got[0].Secrets[0].Name != "GITHUB_TOKEN" || got[0].Secrets[0].Host != "api.github.com" {
		t.Errorf("master's secrets = %+v", got[0].Secrets)
	}
	// An unparsable spec (which planTeam's own checkAgentPolicy would already
	// have refused before this is ever reached in practice) is skipped rather
	// than panicking a view that is meant to be read-only.
	if len(got[1].Secrets) != 0 {
		t.Errorf("an unparsable secret spec produced an entry: %+v", got[1].Secrets)
	}
}

func TestGraphAgentsAndStoreFromTopologyReadTheRecordedEvent(t *testing.T) {
	topo := recorder.NewTeamTopology(recorder.TopologyFields{
		Agents:    []recorder.EvAgent{{Name: "master", Sandbox: "abc", Group: "g1"}},
		StoreKeys: []recorder.EvStoreKey{{Name: "findings", Read: []string{"master"}}},
	})
	policy := recorder.NewSessionPolicy("master", recorder.PolicyFields{Allow: []string{"example.com"}})
	agents := graphAgentsFromTopology(&topo, map[string]*digest.Agent{
		"master": {Name: "master", Policy: &policy},
	})
	if len(agents) != 1 || agents[0].Group != "g1" || len(agents[0].Allow) != 1 || agents[0].Allow[0] != "example.com" {
		t.Errorf("graphAgentsFromTopology = %+v", agents)
	}
	store := graphStoreFromTopology(&topo)
	if len(store) != 1 || store[0].Name != "findings" {
		t.Errorf("graphStoreFromTopology = %+v", store)
	}
}

// The picture and the authoritative edge list must both draw something for a
// simple star, and TransitiveClosure must find the two-hop reach a direct
// reading of the edges alone would miss — the OWASP transitive-privilege
// case this whole view exists to surface.
func TestRenderTeamGraphDrawsTheCanvasEdgesAndIndirectReach(t *testing.T) {
	in := graph.Input{
		Agents: []graph.Agent{{ID: "master"}, {ID: "worker-1"}, {ID: "worker-2"}},
		Edges: []graph.Edge{
			{From: "master", To: "worker-1"}, {From: "worker-1", To: "master"},
			{From: "master", To: "worker-2"}, {From: "worker-2", To: "master"},
		},
	}
	var b strings.Builder
	if err := renderTeamGraph(&b, in, "title line"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"title line", "master", "worker-1", "worker-2",
		"edges — read from the authoritative table", "indirect reach"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q:\n%s", want, out)
		}
	}
	// worker-1 -> worker-2 has no direct edge but is reachable in two hops
	// through master.
	if !strings.Contains(out, "worker-1 -> worker-2 (2 hops") {
		t.Errorf("indirect reach through the hub was not reported:\n%s", out)
	}
}

// The bug a review caught: internal/graph.TransitiveClosure makes a shared
// StoreKey a ONE-hop relation (a write->read pair), the same as a declared
// edge — but the old filter only reported a pair as "indirect reach" when
// hops > 1, so every store-mediated reach, including the whole-team default
// access unmatchedStoreKeyID grants, was silently dropped. Two agents with
// NO declared edges and one store both may read and write: they reach each
// other in exactly one hop, through no edge at all, and the section must
// say so.
func TestRenderTeamGraphReportsOneHopStoreMediatedReachAsIndirect(t *testing.T) {
	in, err := buildGraphInput(
		[]graphAgent{{Name: "worker-1"}, {Name: "worker-2"}},
		nil, // no declared edges at all
		[]graphStoreRule{{Name: "shared", Read: []string{"*"}, Write: []string{"*"}}},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := renderTeamGraph(&b, in, "title"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "indirect reach") {
		t.Fatalf("no indirect-reach section for a store-only, edge-free pair:\n%s", out)
	}
	for _, want := range []string{"worker-1 -> worker-2 (1 hop", "worker-2 -> worker-1 (1 hop"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q — a one-hop, store-mediated reach was not reported:\n%s", want, out)
		}
	}
}

// Every pair NOT in in.Edges and reachable at all is reported, regardless
// of hop count — direct edges themselves must never appear in the
// "indirect reach" section (they are not indirect).
func TestRenderTeamGraphNeverReportsADirectEdgeAsIndirectReach(t *testing.T) {
	in := graph.Input{
		Agents: []graph.Agent{{ID: "a"}, {ID: "b"}},
		Edges:  []graph.Edge{{From: "a", To: "b"}},
	}
	var b strings.Builder
	if err := renderTeamGraph(&b, in, "title"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "indirect reach") {
		t.Errorf("a two-agent team with only a direct edge got an indirect-reach section:\n%s", out)
	}
}

// Bounded, and saying so when it truncates: a large team makes this list
// close to quadratic once a store is enabled (every pair reaches in one
// hop), and it must not be allowed to print without limit.
func TestRenderTeamGraphIndirectReachIsBoundedAndSaysSoWhenTruncated(t *testing.T) {
	var agents []graphAgent
	for i := 0; i < 30; i++ {
		agents = append(agents, graphAgent{Name: fmt.Sprintf("worker-%02d", i)})
	}
	in, err := buildGraphInput(agents, nil,
		[]graphStoreRule{{Name: "shared", Read: []string{"*"}, Write: []string{"*"}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := renderTeamGraph(&b, in, "title"); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if got := strings.Count(out, "hop"); got > maxIndirectReachLines {
		t.Errorf("printed %d indirect-reach lines, want at most the bound of %d", got, maxIndirectReachLines)
	}
	if !strings.Contains(out, "more pair(s) not shown") {
		t.Errorf("no truncation notice for a 30-agent, fully-open store:\n%s", out)
	}
}

// A domain or a secret access is drawn "reaches"/"uses" regardless of the
// underlying EdgeKind, which is meaningless for either (internal/graph's own
// Access doc comment) — only a StoreKey's read/write distinction is real.
func TestEdgeArrowLabelsDomainAndSecretAccessDistinctlyFromStoreKeys(t *testing.T) {
	if got := edgeArrow(graph.EdgeRead, graph.Domain); got != "reaches" {
		t.Errorf("domain access = %q, want reaches", got)
	}
	if got := edgeArrow(graph.EdgeRead, graph.Secret); got != "uses" {
		t.Errorf("secret access = %q, want uses", got)
	}
	if got := edgeArrow(graph.EdgeRead, graph.StoreKey); got != "reads" {
		t.Errorf("store-key read = %q, want reads", got)
	}
	if got := edgeArrow(graph.EdgeWrite, graph.StoreKey); got != "writes" {
		t.Errorf("store-key write = %q, want writes", got)
	}
}

// A guest-chosen peer name — internal/team/broker.go writes a team.refused's
// Peer verbatim for a recipient outside the team — must never reach this
// view's output carrying a raw control byte that could rewrite the terminal
// line it is printed on (proto.SafeText, no exceptions).
func TestPrintRecentRefusalsAppliesSafeTextToAGuestChosenPeer(t *testing.T) {
	hostile := "worker-9\x1b[2K\x1b[1;1Hpwned"
	d := digest.Walk([]recorder.Event{
		{Type: recorder.TypeTeamRefused, Agent: "worker-1", Peer: hostile, Kind: "send", Reason: "no_edge"},
	})
	var b strings.Builder
	printRecentRefusals(&b, d)
	out := b.String()
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("a raw ESC byte from a guest-chosen peer name reached the output:\n%q", out)
	}
	if !strings.Contains(out, "refused since boot") {
		t.Errorf("no refusal section: %q", out)
	}
	if !strings.Contains(out, "add [[team.edge]]") {
		t.Errorf("the fix line from internal/denial is missing: %q", out)
	}
}

// A store denial's fix line names the right verb: get/put/delete map to
// read/write, the same distinction internal/team/store.go's own may() draws.
func TestPrintRecentRefusalsNamesTheRightVerbForAStoreDenial(t *testing.T) {
	d := digest.Walk([]recorder.Event{
		{Type: recorder.TypeTeamStore, Agent: "worker-2", Peer: "findings/worker-1", Kind: "get",
			Outcome: "refused", Reason: "denied"},
	})
	var b strings.Builder
	printRecentRefusals(&b, d)
	out := b.String()
	if !strings.Contains(out, "read") {
		t.Errorf("a get denial's fix line does not say \"read\": %q", out)
	}
}

// Output is bounded, and says so when it truncates — the same rule
// internal/digest already applies to its own counters, applied here to what
// this view prints so a hostile session cannot make the terminal's own
// output unbounded.
func TestPrintRecentRefusalsIsBoundedAndSaysSoWhenTruncated(t *testing.T) {
	var events []recorder.Event
	for i := 0; i < maxRefusalLines+5; i++ {
		events = append(events, recorder.Event{
			Type: recorder.TypeTeamRefused, Agent: "worker-1", Peer: "ghost", Kind: "send", Reason: "no_edge",
		})
	}
	d := digest.Walk(events)
	var b strings.Builder
	printRecentRefusals(&b, d)
	out := b.String()
	if !strings.Contains(out, "earlier refusal") {
		t.Errorf("no truncation notice for %d refusals: %q", len(events), out)
	}
	if strings.Count(out, "add [[team.edge]]") != maxRefusalLines {
		t.Errorf("printed %d fix lines, want the bound of %d", strings.Count(out, "add [[team.edge]]"), maxRefusalLines)
	}
}

// "refused since boot" used to cover only two of the reasons
// team.refused/team.store/team.spawn can carry, which reads as complete
// when it is not — a review's finding. refusalLine now covers every real
// refusal reason each of the three event types can carry; this proves each
// one is recognised (ok == true) and, where internal/denial has a matching
// entry, carries that exact fix line.
func TestRefusalLineCoversEveryRefusalReason(t *testing.T) {
	cases := []struct {
		name string
		e    recorder.Event
		want string // substring the line must contain
	}{
		{"no_edge", recorder.Event{Type: recorder.TypeTeamRefused, Agent: "a", Peer: "b", Reason: "no_edge"},
			"add [[team.edge]]"},
		{"no_such_agent", recorder.Event{Type: recorder.TypeTeamRefused, Agent: "a", Peer: "ghost", Reason: "no_such_agent"},
			"is not in this team"},
		{"missing_correlation", recorder.Event{Type: recorder.TypeTeamRefused, Agent: "a", Reason: "missing_correlation"},
			"carried no correlate tag"},
		{"unknown_correlation", recorder.Event{Type: recorder.TypeTeamRefused, Agent: "a", Reason: "unknown_correlation"},
			"matched no outstanding question"},
		{"store denied", recorder.Event{Type: recorder.TypeTeamStore, Agent: "a", Peer: "k", Kind: "get",
			Outcome: "refused", Reason: "denied"}, "add \"a\" to read"},
		{"store key_too_long", recorder.Event{Type: recorder.TypeTeamStore, Agent: "a", Kind: "put",
			Outcome: "refused", Reason: "key_too_long"}, "tried a store key over"},
		{"store value_too_large", recorder.Event{Type: recorder.TypeTeamStore, Agent: "a", Kind: "put",
			Outcome: "refused", Reason: "value_too_large"}, "more than"},
		{"store too_many_keys", recorder.Event{Type: recorder.TypeTeamStore, Agent: "a", Kind: "put",
			Outcome: "refused", Reason: "too_many_keys"}, "key store limit"},
		{"store store_full", recorder.Event{Type: recorder.TypeTeamStore, Agent: "a", Kind: "put",
			Outcome: "refused", Reason: "store_full"}, "byte store limit"},
		{"spawn no_spawn_budget", recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "a", Kind: "spawn",
			Outcome: "refused", Reason: "no_spawn_budget"}, "has no spawn budget"},
		{"spawn budget_exhausted", recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "a", Kind: "spawn",
			Outcome: "refused", Reason: "budget_exhausted"}, "budget allows"},
		{"spawn image_not_permitted", recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "a", Kind: "spawn",
			Outcome: "refused", Reason: "image_not_permitted"}, "does not permit"},
		{"spawn name_taken", recorder.Event{Type: recorder.TypeTeamSpawn, Agent: "a", Peer: "a-spawn-1", Kind: "spawn",
			Outcome: "refused", Reason: "name_taken"}, "collided with an existing agent name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, ok := refusalLine(tc.e)
			if !ok {
				t.Fatalf("refusalLine did not recognise reason %q", tc.e.Reason)
			}
			if !strings.Contains(line, tc.want) {
				t.Errorf("line = %q, want it to contain %q", line, tc.want)
			}
		})
	}
}

// Two reasons are deliberately excluded, and this pins that they stay
// excluded rather than reappearing by accident: team.store's "no_such_key"
// is an absence, not a refusal (docs/teams.md's own words), and
// team.spawn's despawn-side "not_a_spawned_worker" is an internal condition
// nobody watching a team's policy file can act on. A delivered event of any
// type is excluded too.
func TestRefusalLineExcludesAbsenceAndInternalConditions(t *testing.T) {
	cases := []recorder.Event{
		{Type: recorder.TypeTeamStore, Agent: "a", Kind: "get", Outcome: "refused", Reason: "no_such_key"},
		{Type: recorder.TypeTeamSpawn, Kind: "despawn", Outcome: "refused", Reason: "not_a_spawned_worker"},
		{Type: recorder.TypeTeamStore, Agent: "a", Kind: "get", Outcome: "delivered"},
		{Type: recorder.TypeTeamSpawn, Agent: "a", Kind: "spawn", Outcome: "delivered"},
		{Type: recorder.TypeTeamMessage, Agent: "a", Peer: "b", Kind: "send"},
	}
	for _, e := range cases {
		if line, ok := refusalLine(e); ok {
			t.Errorf("reason %q (type %s) was not excluded: %q", e.Reason, e.Type, line)
		}
	}
}

// A worker spawned at runtime (broker.OnSpawn) is real but never appears in
// the boot-time team.topology event — spawnedAgentsNotInTopology is what
// lets the view say so explicitly instead of silently blending "declared"
// and "actual" into one answer (a review's finding).
func TestSpawnedAgentsNotInTopology(t *testing.T) {
	topo := recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: []recorder.EvAgent{{Name: "master"}, {Name: "worker-1"}},
	})
	agents := map[string]*digest.Agent{
		"master":         {Name: "master"},
		"worker-1":       {Name: "worker-1"},
		"master-spawn-1": {Name: "master-spawn-1"},
		"master-spawn-2": {Name: "master-spawn-2"},
	}
	got := spawnedAgentsNotInTopology(&topo, agents)
	if strings.Join(got, ",") != "master-spawn-1,master-spawn-2" {
		t.Errorf("spawnedAgentsNotInTopology = %v, want just the two spawned workers, sorted", got)
	}

	// Every declared agent present and nobody spawned: nothing extra.
	none := spawnedAgentsNotInTopology(&topo, map[string]*digest.Agent{
		"master": {Name: "master"}, "worker-1": {Name: "worker-1"},
	})
	if len(none) != 0 {
		t.Errorf("declared-only agents reported as spawned: %v", none)
	}
}

// fitToBudget must never emit more than budget lines, note included — the
// off-by-one a review caught: the old per-pane logic picked a full budget's
// worth of content and then appended a truncation note on top, emitting
// budget+1 lines every time it truncated.
func TestFitToBudgetNeverExceedsItsBudget(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	note := "…more"
	for budget := 0; budget <= len(lines)+2; budget++ {
		got := fitToBudget(lines, budget, note)
		if len(got) > budget {
			t.Errorf("budget %d: got %d lines (%v), want at most %d", budget, len(got), got, budget)
		}
	}
	// Under budget: nothing is cut, and the note never appears.
	if got := fitToBudget(lines, 100, note); len(got) != len(lines) {
		t.Errorf("a budget larger than the content still truncated: %v", got)
	}
	// Over budget: the note is present and is the last line.
	got := fitToBudget(lines, 3, note)
	if len(got) != 3 || got[2] != note {
		t.Errorf("fitToBudget(lines, 3, note) = %v, want 3 lines ending in the note", got)
	}
}

// P7-10: kelyfos team graph --json / kelyfos team ps --graph --json.
//
// buildTeamGraphJSON is a pure conversion of an already-normalized
// graph.Input, so these tests build the Input directly (as
// TestRenderTeamGraphDrawsTheCanvasEdgesAndIndirectReach and its siblings
// already do) rather than going through buildGraphInput again — the two are
// tested separately, on purpose, so a bug in one is not masked by the other.

func TestBuildTeamGraphJSONReportsAgentsEdgesResourcesAndAccess(t *testing.T) {
	in := graph.Input{
		Agents:    []graph.Agent{{ID: "master", Group: "g"}, {ID: "worker-1"}},
		Edges:     []graph.Edge{{From: "master", To: "worker-1"}},
		Resources: []graph.Resource{{ID: "example.com", Kind: graph.Domain}, {ID: "findings", Kind: graph.StoreKey}},
		Access: []graph.Access{
			{Agent: "master", Resource: "example.com"},
			{Agent: "worker-1", Resource: "findings", Write: true},
		},
	}
	out, err := buildTeamGraphJSON("declared", "suppliers", in, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Mode != "declared" || out.Team != "suppliers" {
		t.Errorf("Mode=%q Team=%q, want declared/suppliers", out.Mode, out.Team)
	}
	if len(out.Agents) != 2 || out.Agents[0].ID != "master" || out.Agents[0].Group != "g" {
		t.Errorf("Agents = %+v, want master (group g) and worker-1", out.Agents)
	}
	if len(out.Edges) != 1 || out.Edges[0] != (teamGraphEdgeJSON{From: "master", To: "worker-1"}) {
		t.Errorf("Edges = %+v", out.Edges)
	}
	if len(out.Resources) != 2 || out.Resources[0].Kind != "domain" || out.Resources[1].Kind != "store_key" {
		t.Errorf("Resources = %+v, want kinds domain then store_key", out.Resources)
	}
	if len(out.Access) != 2 || !out.Access[1].Write {
		t.Errorf("Access = %+v, want worker-1's findings access to carry write=true", out.Access)
	}
	if len(out.EgressPorts) == 0 {
		t.Error("EgressPorts is empty — every sandbox reaches the fixed default pair (P7-4/D65)")
	}
	if out.SpawnedNotInTopology != nil || out.StoreEnabledUnknown {
		t.Errorf("declared mode carries running-only fields: spawned=%v unknown=%v",
			out.SpawnedNotInTopology, out.StoreEnabledUnknown)
	}
}

// Same fixture and the same expectation as
// TestRenderTeamGraphReportsOneHopStoreMediatedReachAsIndirect: the JSON
// shape and the terminal drawing must never disagree about what reaches what.
func TestBuildTeamGraphJSONReportsOneHopStoreMediatedReachAsIndirect(t *testing.T) {
	in, err := buildGraphInput(
		[]graphAgent{{Name: "worker-1"}, {Name: "worker-2"}},
		nil,
		[]graphStoreRule{{Name: "shared", Read: []string{"*"}, Write: []string{"*"}}},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildTeamGraphJSON("declared", "t", in, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[[2]string]int{{"worker-1", "worker-2"}: 1, {"worker-2", "worker-1"}: 1}
	if len(out.IndirectReach) != len(want) {
		t.Fatalf("IndirectReach = %+v, want %d one-hop pairs", out.IndirectReach, len(want))
	}
	for _, r := range out.IndirectReach {
		hops, ok := want[[2]string{r.From, r.To}]
		if !ok || hops != r.Hops {
			t.Errorf("unexpected reach entry %+v", r)
		}
	}
}

// Mirrors TestRenderTeamGraphNeverReportsADirectEdgeAsIndirectReach: a
// declared edge must never also appear in IndirectReach.
func TestBuildTeamGraphJSONNeverReportsADirectEdgeAsIndirectReach(t *testing.T) {
	in := graph.Input{
		Agents: []graph.Agent{{ID: "a"}, {ID: "b"}},
		Edges:  []graph.Edge{{From: "a", To: "b"}},
	}
	out, err := buildTeamGraphJSON("declared", "t", in, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.IndirectReach) != 0 {
		t.Errorf("a direct edge showed up in IndirectReach: %+v", out.IndirectReach)
	}
}

// Mirrors TestRenderTeamGraphIndirectReachIsBoundedAndSaysSoWhenTruncated:
// the JSON shape must bound the same list the same way and say when it did.
func TestBuildTeamGraphJSONIndirectReachIsBoundedAndSaysSoWhenTruncated(t *testing.T) {
	var agents []graphAgent
	for i := 0; i < 30; i++ {
		agents = append(agents, graphAgent{Name: fmt.Sprintf("worker-%02d", i)})
	}
	in, err := buildGraphInput(agents, nil,
		[]graphStoreRule{{Name: "shared", Read: []string{"*"}, Write: []string{"*"}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildTeamGraphJSON("declared", "t", in, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.IndirectReach) > maxIndirectReachLines {
		t.Errorf("IndirectReach has %d entries, want at most %d", len(out.IndirectReach), maxIndirectReachLines)
	}
	if !out.IndirectReachTruncated {
		t.Error("a 30-agent, fully-open store did not set IndirectReachTruncated")
	}
}

func TestBuildTeamGraphJSONRunningModeCarriesTheTwoHonestGaps(t *testing.T) {
	in := graph.Input{Agents: []graph.Agent{{ID: "master"}}}
	out, err := buildTeamGraphJSON("running", "t", in, true, []string{"master-spawn-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Mode != "running" {
		t.Errorf("Mode = %q, want running", out.Mode)
	}
	if !out.StoreEnabledUnknown {
		t.Error("StoreEnabledUnknown not set when the caller said it was unknown")
	}
	if strings.Join(out.SpawnedNotInTopology, ",") != "master-spawn-1" {
		t.Errorf("SpawnedNotInTopology = %v, want [master-spawn-1]", out.SpawnedNotInTopology)
	}
}

// A hostile agent name — a <script> tag, a null byte, a quote that would
// break a hand-built JSON string — must reach valid, well-escaped JSON and
// nothing else: encoding/json escapes correctly by construction, so this
// asserts that property holds end to end rather than assuming it.
func TestBuildTeamGraphJSONMarshalsHostileNamesSafely(t *testing.T) {
	hostile := "worker\"</script><script>alert(1)</script>\x00\x1b[31m"
	in := graph.Input{
		Agents:    []graph.Agent{{ID: graph.AgentID(hostile)}, {ID: "master"}},
		Edges:     []graph.Edge{{From: graph.AgentID(hostile), To: "master"}},
		Resources: []graph.Resource{{ID: graph.ResourceID(hostile), Kind: graph.Domain}},
		Access:    []graph.Access{{Agent: graph.AgentID(hostile), Resource: graph.ResourceID(hostile)}},
	}
	out, err := buildTeamGraphJSON("declared", hostile, in, false, []string{hostile})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal refused hostile input: %v", err)
	}
	if strings.Contains(string(blob), "<script") {
		t.Errorf("raw <script bytes reached the marshaled JSON: %s", blob)
	}
	if strings.ContainsAny(string(blob), "\x00\x1b") {
		t.Errorf("a raw control byte reached the marshaled JSON: %q", blob)
	}
	var back teamGraphJSON
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("the marshaled JSON does not parse back: %v", err)
	}
	// in.Agents is [hostile, "master"], in that order, and buildTeamGraphJSON
	// walks in.Agents directly (no sort) — so index 0 is the hostile one.
	if back.Team != hostile || back.Agents[0].ID != hostile {
		t.Errorf("the hostile value did not round-trip intact: Team=%q Agents[0].ID=%q", back.Team, back.Agents[0].ID)
	}
}

func TestTeamPSJSONMarshalsAndRoundTrips(t *testing.T) {
	in := teamPSJSON{
		Team: "suppliers", Session: "abc123", Owner: ownerCLI, StartedAt: "2026-08-27T00:00:00Z",
		Edges:  []string{"master -> worker-1"},
		Budget: &teamBudget{CGroup: "kelyfos.slice", CPUQuota: 200, UsedSeconds: 1.5},
		Agents: []teamMember{{Name: "master", Sandbox: "sb1", Alive: true}},
	}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back teamPSJSON
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("does not round-trip: %v", err)
	}
	if back.Team != in.Team || back.Budget.CGroup != in.Budget.CGroup || len(back.Agents) != 1 {
		t.Errorf("round trip mismatch: got %+v", back)
	}
}
