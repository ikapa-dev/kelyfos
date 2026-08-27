package main

import (
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

	in, err := buildGraphInput(agents, nil, store)
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

	// A team with no store rules at all gets no synthetic resource: there is
	// nothing declared for it to stand in for.
	empty, err := buildGraphInput(agents, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range empty.Resources {
		if r.ID == unmatchedStoreKeyID {
			t.Error("a team with zero store rules still got the synthetic unmatched-key resource")
		}
	}
}

func TestBuildGraphInputResolvesDomainsAndSecretsPerAgent(t *testing.T) {
	agents := []graphAgent{
		{Name: "master", Allow: []string{"example.com"}, Secrets: []recorder.EvSecret{{Name: "TOK", Host: "example.com"}}},
		{Name: "worker"},
	}
	in, err := buildGraphInput(agents, []string{"master -> worker"}, nil)
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
	if _, err := buildGraphInput(agents, []string{"a --- b"}, nil); err == nil {
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
