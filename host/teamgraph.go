package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/graph"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
	"github.com/p4r4n0rm4l/KelyfOS/internal/team"
)

// P7-7: the terminal views. `kelyfos team graph` renders a team's topology
// straight from kelyfos.toml with nothing booted — a pre-flight lint in the
// category of `kelyfos doctor`, not a monitor, going through the exact
// plan-time path P7-4's checkTeamFileScope lint uses (planTeam), so a
// [[plugin]]/[[forward]] mistake beside [team] is refused here with the same
// sentence `kelyfos team up` would refuse it with, before anything boots.
// `kelyfos team ps --graph` (host/team.go) does the same for a running team,
// reading the team's own recorded team.topology and session.policy events
// rather than kelyfos.toml (which the user can edit afterwards) or
// run/team.json (which does not outlive the run) — D59's reasoning for
// putting the declaration in the chain in the first place.
//
// This file names the three modes P7-7 introduces and the rest of Phase 7
// reuses: *declared* (kelyfos.toml, nothing booted — teamGraphCmd),
// *aggregate* (a fold of what happened — internal/digest's counters, drawn
// in the agent sheet), *as-it-ran* (the live/replayed timeline — kelyfos
// watch and kelyfos log already are this). Only declared is something
// anyone else — an auditor, a teammate reading the file — can currently
// answer without booting anything.
//
// One graph.Input builder (buildGraphInput) serves both commands and
// kelyfos watch's map pane, fed by two small adapters
// (graphAgentsFromPlan/graphStoreFromPlan for the declared path,
// graphAgentsFromTopology/graphStoreFromTopology for the recorded one) — so
// a declared graph and a running one are always the same conversion, never
// two renderers that happen to agree today.

func teamGraphCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos team graph", flag.ExitOnError)
	named := fs.String("policy", "", "a specific kelyfos.toml, instead of the one found by walking up from here")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos team graph [flags]

Renders the team topology declared in kelyfos.toml, with nothing booted: a
pre-flight lint in the category of `+"`kelyfos doctor`"+`, not a monitor. Runs the
same plan-time checks `+"`kelyfos team up`"+` runs before it boots anything — a
[[plugin]] or [[forward]] beside [team] is refused here with the same
sentence, before it costs somebody an afternoon.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	cfg, err := loadPolicyAt(*named)
	if err != nil {
		return err
	}
	if cfg == nil || cfg.Team == nil {
		return fmt.Errorf("no [team] section in this project's %s — see docs/teams.md", config.FileName)
	}
	plan, err := planTeam(cfg)
	if err != nil {
		return err
	}
	if err := checkTeamScratch(plan); err != nil {
		return err
	}

	in, err := buildGraphInput(graphAgentsFromPlan(plan), plan.edgeText, graphStoreFromPlan(plan), plan.storeEnabled)
	if err != nil {
		return err
	}

	title := fmt.Sprintf("team %s — declared topology (kelyfos team graph), nothing booted: %d agents, %d edges",
		proto.SafeText(plan.name), len(plan.agents), len(plan.edgeText))
	if err := renderTeamGraph(os.Stdout, in, title); err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("egress ports: every reachable domain, %s only — the fixed default (docs/networking.md, P7-4)\n",
		portList(egress.DefaultPorts()))
	return nil
}

// teamPSGraph is `kelyfos team ps --graph`: the same rendering as `kelyfos
// team graph`, sourced from the running team's own flight recorder rather
// than kelyfos.toml. It reads the team's shared chain for its team.topology
// event (P7-3) and every agent's session.policy (P7-2) through
// internal/digest — the same fold kelyfos watch absorbs live — so a running
// team's graph and a declared one are never two independent readings of the
// same file.
func teamPSGraph(st *teamState) error {
	f, err := os.Open(recorder.Path(sandbox.Root(), st.Session))
	if err != nil {
		return fmt.Errorf("reading session %s: %w", st.Session, err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		return fmt.Errorf("session %s: %w", st.Session, err)
	}
	d := digest.Walk(events)
	if d.Topology == nil {
		return fmt.Errorf("session %s carries no team.topology event yet — either this team is still "+
			"coming up, or it was booted by a kelyfos older than P7-3", st.Session)
	}

	agents := graphAgentsFromTopology(d.Topology, d.Agents)
	store := graphStoreFromTopology(d.Topology)
	// See buildGraphInput's own doc comment: team.topology carries no
	// "store enabled" flag independent of its rule count, so a store
	// enabled with zero [[team.store.key]] rules cannot be told apart from
	// no store at all, from this event alone. Best-effort here, and the
	// caveat below says so rather than leaving the gap silent.
	storeEnabled := len(store) > 0
	in, err := buildGraphInput(agents, d.Topology.Edges, store, storeEnabled)
	if err != nil {
		return err
	}

	title := fmt.Sprintf("team %s — topology as declared at boot (kelyfos team ps --graph): %d agents, %d edges",
		proto.SafeText(st.Name), len(d.Topology.Agents), len(d.Topology.Edges))
	if err := renderTeamGraph(os.Stdout, in, title); err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("egress ports: every reachable domain, %s only — the fixed default (docs/networking.md, P7-4)\n",
		portList(egress.DefaultPorts()))
	if len(store) == 0 {
		fmt.Println()
		fmt.Println("note: this session's team.topology names no [[team.store.key]] rule, and the record")
		fmt.Println("does not say whether [team.store] is even enabled (a P7-3 recorder gap, not this")
		fmt.Println("view's). If the store IS enabled, every key is team-wide by default and would not")
		fmt.Println("appear as a resource above.")
	}
	if extra := spawnedAgentsNotInTopology(d.Topology, d.Agents); len(extra) > 0 {
		fmt.Println()
		fmt.Printf("+%d agent(s) spawned at runtime, not in the topology declared at boot above "+
			"(team.spawn only, no team.topology entry): %s\n", len(extra), safeJoinNames(extra, maxSpawnedNamesShown))
	}
	printRecentRefusals(os.Stdout, d)
	return nil
}

// spawnedAgentsNotInTopology names every agent internal/digest has seen —
// meaning it generated at least one event of its own, such as its own
// session.ready/session.policy once P7-2's OnSpawn extension writes them —
// that the boot-time team.topology event does not list. team.topology is
// written once, at boot (docs/policy-record.md §3); a worker a running agent
// spawns afterwards (broker.OnSpawn) attaches with a real edge and store
// access that event can never carry, and merging it silently into the
// declared picture would blur exactly the declared-vs-actual distinction
// this task's three-mode naming exists to keep clear. Sorted, for a stable
// and testable order.
func spawnedAgentsNotInTopology(topo *recorder.Event, agentDigests map[string]*digest.Agent) []string {
	known := map[string]bool{}
	for _, a := range topo.Agents {
		known[a.Name] = true
	}
	var extra []string
	for name := range agentDigests {
		if !known[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	return extra
}

// maxSpawnedNamesShown bounds safeJoinNames, so a runtime-spawn loop cannot
// make this note's own line grow without bound.
const maxSpawnedNamesShown = 20

// safeJoinNames renders a list of agent names — each safe on its own,
// clamped to nodeLabelWidth — as one comma-separated, bounded line, with a
// trailing count of what was left out rather than growing forever.
func safeJoinNames(names []string, max int) string {
	shown := names
	var suffix string
	if len(shown) > max {
		suffix = fmt.Sprintf(", … and %d more", len(shown)-max)
		shown = shown[:max]
	}
	safe := make([]string, len(shown))
	for i, n := range shown {
		safe[i] = clampWidth(proto.SafeText(n), nodeLabelWidth)
	}
	return strings.Join(safe, ", ") + suffix
}

// graphAgent is one team member as internal/graph needs it, gathered from
// either a not-yet-booted plan or a running team's own recorded events — the
// one shape buildGraphInput reads, regardless of which mode produced it.
type graphAgent struct {
	Name, Group string
	Allow       []string
	Secrets     []recorder.EvSecret
}

// graphStoreRule is one [[team.store.key]] rule, in the shape both a plan
// (team.Rule, via plannedAgent) and a recorded team.topology
// (recorder.EvStoreKey) already carry: a name (possibly a glob) and its
// read/write lists, themselves possibly "*" or a glob.
type graphStoreRule struct {
	Name        string
	Read, Write []string
}

// unmatchedStoreKeyID names the synthetic resource standing for every store
// key no [[team.store.key]] rule matches — team-wide by default
// (internal/team/store.go: "No rule mentions this key, so it belongs to the
// whole team."). internal/graph's own package doc names synthesizing this
// access the caller's obligation, because only the caller knows which keys
// had no rule at all; omitting it would understate what the team can touch,
// the one direction a reach view must never fail in. The literal set of
// unmatched keys is not knowable ahead of any team_store_put, so one resource
// stands for all of them rather than enumerating keys that do not exist yet.
// Chosen to be unlikely to collide with a real rule's Name; rendered as
// prose, never treated as a literal key.
const unmatchedStoreKeyID = "(any other key)"

// buildGraphInput turns a team's resolved shape into internal/graph's Input.
// The one conversion both teamGraphCmd (declared) and teamPSGraph (running)
// use, so the two commands cannot draw two different pictures of one
// topology — and the place graph.Input's own caller obligation is honoured:
// a StoreKey resource is added for every declared rule, and one more for
// every key no rule names (see unmatchedStoreKeyID), with the whole team
// granted access to it.
//
// storeEnabled and store are independent (host/teamplan.go's teamPlan draws
// them as two separate fields, storeEnabled and storeRules): a team can have
// [team.store] enabled with zero [[team.store.key]] rules, in which case
// EVERY key is team-wide by default (internal/team/store.go) and the
// unmatched-key resource has to appear even though store is empty — gating
// it on len(store) > 0 alone was the bug a review caught (a 3-agent team
// with an empty, enabled store drew no store node at all). Passing
// storeEnabled := len(store) > 0 at a call site that cannot know the real
// flag (team.topology carries none) is a documented, honest approximation,
// not silently wrong — see teamPSGraph's own caveat to the reader.
func buildGraphInput(agents []graphAgent, edges []string, store []graphStoreRule, storeEnabled bool) (graph.Input, error) {
	var in graph.Input
	names := make([]string, 0, len(agents))
	for _, a := range agents {
		in.Agents = append(in.Agents, graph.Agent{ID: graph.AgentID(a.Name), Group: a.Group})
		names = append(names, a.Name)
	}

	for _, e := range edges {
		from, to, ok := strings.Cut(e, " -> ")
		if !ok {
			return graph.Input{}, fmt.Errorf("team graph: edge %q is not of the form \"from -> to\"", e)
		}
		in.Edges = append(in.Edges, graph.Edge{From: graph.AgentID(from), To: graph.AgentID(to)})
	}

	resSeen := map[graph.ResourceID]bool{}
	addResource := func(id graph.ResourceID, kind graph.ResourceKind) {
		if resSeen[id] {
			return
		}
		resSeen[id] = true
		in.Resources = append(in.Resources, graph.Resource{ID: id, Kind: kind})
	}

	for _, a := range agents {
		for _, domain := range a.Allow {
			rid := graph.ResourceID(domain)
			addResource(rid, graph.Domain)
			in.Access = append(in.Access, graph.Access{Agent: graph.AgentID(a.Name), Resource: rid})
		}
		for _, s := range a.Secrets {
			rid := graph.ResourceID(s.Name + "@" + s.Host)
			addResource(rid, graph.Secret)
			in.Access = append(in.Access, graph.Access{Agent: graph.AgentID(a.Name), Resource: rid})
		}
	}

	for _, rule := range store {
		rid := graph.ResourceID(rule.Name)
		addResource(rid, graph.StoreKey)
		for _, name := range expandStoreSpecs(rule.Read, names) {
			in.Access = append(in.Access, graph.Access{Agent: graph.AgentID(name), Resource: rid, Write: false})
		}
		for _, name := range expandStoreSpecs(rule.Write, names) {
			in.Access = append(in.Access, graph.Access{Agent: graph.AgentID(name), Resource: rid, Write: true})
		}
	}
	if storeEnabled {
		rid := graph.ResourceID(unmatchedStoreKeyID)
		addResource(rid, graph.StoreKey)
		for _, name := range names {
			in.Access = append(in.Access, graph.Access{Agent: graph.AgentID(name), Resource: rid, Write: false})
			in.Access = append(in.Access, graph.Access{Agent: graph.AgentID(name), Resource: rid, Write: true})
		}
	}

	return in, nil
}

// expandStoreSpecs resolves a [[team.store.key]] rule's read/write list
// against the team's actual agent names: "*" for everyone, "worker-*" for a
// prefix, or one literal name — the same three shapes
// internal/team/store.go's own may() accepts, so a graph view and the
// runtime enforcement it draws can never disagree about who a rule grants.
func expandStoreSpecs(specs, agents []string) []string {
	var out []string
	for _, spec := range specs {
		if spec == "*" {
			out = append(out, agents...)
			continue
		}
		if prefix, ok := strings.CutSuffix(spec, "*"); ok {
			for _, a := range agents {
				if strings.HasPrefix(a, prefix) {
					out = append(out, a)
				}
			}
			continue
		}
		out = append(out, spec)
	}
	return out
}

// graphAgentsFromPlan is the declared-mode adapter: a plan nothing has
// booted yet, straight from planTeam.
func graphAgentsFromPlan(plan *teamPlan) []graphAgent {
	out := make([]graphAgent, len(plan.agents))
	for i, a := range plan.agents {
		var secrets []recorder.EvSecret
		for _, spec := range a.secrets {
			// checkAgentPolicy (called from planTeam) has already validated
			// every secret spec on this agent, so ParseSecretSpec cannot
			// fail here in practice; skip rather than invent a value if it
			// somehow does.
			parsed, err := egress.ParseSecretSpec(spec)
			if err != nil {
				continue
			}
			secrets = append(secrets, recorder.EvSecret{Name: parsed.Name, Host: parsed.Host, Path: parsed.Path})
		}
		out[i] = graphAgent{Name: a.name, Allow: a.allow, Secrets: secrets}
	}
	return out
}

func graphStoreFromPlan(plan *teamPlan) []graphStoreRule {
	out := make([]graphStoreRule, len(plan.storeRules))
	for i, r := range plan.storeRules {
		out[i] = graphStoreRule{Name: r.Name, Read: r.Read, Write: r.Write}
	}
	return out
}

// graphAgentsFromTopology is the running-mode adapter: a team.topology event
// (P7-3) for the roster and edges, joined against every agent's own
// session.policy (P7-2), read off internal/digest's fold — policies is
// digest.Digest.Agents, keyed by name, exactly as Absorb built it.
func graphAgentsFromTopology(topo *recorder.Event, agentDigests map[string]*digest.Agent) []graphAgent {
	out := make([]graphAgent, len(topo.Agents))
	for i, a := range topo.Agents {
		ga := graphAgent{Name: a.Name, Group: a.Group}
		if ad := agentDigests[a.Name]; ad != nil && ad.Policy != nil {
			ga.Allow = ad.Policy.Allow
			ga.Secrets = ad.Policy.Secrets
		}
		out[i] = ga
	}
	return out
}

func graphStoreFromTopology(topo *recorder.Event) []graphStoreRule {
	out := make([]graphStoreRule, len(topo.StoreKeys))
	for i, k := range topo.StoreKeys {
		out[i] = graphStoreRule{Name: k.Name, Read: k.Read, Write: k.Write}
	}
	return out
}

// renderTeamGraph draws in to w: the canvas, a legend naming every glyph
// (proto.SafeText on every guest-influenced string), the edge list read from
// Canvas.Edges — the authoritative table, never the rune grid, which a P7-6
// reviewer found can visually misrepresent a topology (a star can draw as a
// chain) — and, when internal/graph's transitive closure finds one, the
// indirect reach a direct-edge reading would miss: the OWASP
// transitive-privilege-inheritance case that is this whole feature's reason
// to exist.
func renderTeamGraph(w io.Writer, in graph.Input, title string) error {
	placement, err := graph.Layout(in)
	if err != nil {
		return err
	}
	canvas := graph.Terminal(placement)
	closure, err := graph.TransitiveClosure(in)
	if err != nil {
		return err
	}

	fmt.Fprintln(w, title)
	if len(canvas.Cells) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, canvas.String())
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "legend")
	for _, n := range canvas.Legend {
		fmt.Fprintf(w, "  %s %s\n", nodeGlyph(n), nodeLabel(n))
	}

	if len(canvas.Edges) > 0 {
		resKind := map[graph.ResourceID]graph.ResourceKind{}
		for _, r := range in.Resources {
			resKind[r.ID] = r.Kind
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "edges — read from the authoritative table, not the picture above")
		for _, e := range canvas.Edges {
			verb := "->"
			if e.To.Kind == graph.NodeResource {
				verb = edgeArrow(e.Kind, resKind[graph.ResourceID(e.To.ID)])
			}
			fmt.Fprintf(w, "  %s %s %s\n",
				clampWidth(proto.SafeText(e.From.ID), nodeLabelWidth), verb,
				clampWidth(proto.SafeText(e.To.ID), nodeLabelWidth))
		}
	}

	// A pair reaches indirectly when TransitiveClosure says it reaches at
	// all and that pair is not one of the input's own declared edges —
	// checked against Hops's own reachability (hops > 0), never against a
	// hop count above one. A shared StoreKey resource is a ONE-hop relation
	// in TransitiveClosure (internal/graph/reach.go's writer->reader edge),
	// the same as a declared team.edge, so filtering on hops > 1 silently
	// dropped every store-mediated reach — including the whole-team default
	// access unmatchedStoreKeyID grants, which makes every ordered pair
	// reach in exactly one hop the moment a store is enabled. That bug
	// hid the entire section for any team with a store (found by review).
	direct := map[[2]graph.AgentID]bool{}
	for _, e := range in.Edges {
		direct[[2]graph.AgentID{e.From, e.To}] = true
	}
	var indirect []string
	for _, from := range closure.Agents {
		for _, to := range closure.Agents {
			if from == to || direct[[2]graph.AgentID{from, to}] {
				continue
			}
			hops, ok := closure.HopsBetween(from, to)
			if !ok {
				continue
			}
			indirect = append(indirect, fmt.Sprintf("  %s -> %s (%d hop%s, no direct edge)",
				clampWidth(proto.SafeText(string(from)), nodeLabelWidth),
				clampWidth(proto.SafeText(string(to)), nodeLabelWidth), hops, plural(hops)))
		}
	}
	if len(indirect) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "indirect reach — reachable through another agent or a shared store key, not a")
		fmt.Fprintln(w, "declared edge: a star topology is not the isolation it looks like")
		// Bounded, and saying so when it truncates: this list is close to
		// quadratic in agent count once a team-wide store default resource
		// makes every ordered pair reach in one hop (a 31-agent star with no
		// store prints 870 lines unbounded before this cap).
		if len(indirect) > maxIndirectReachLines {
			fmt.Fprintf(w, "  … %d more pair(s) not shown\n", len(indirect)-maxIndirectReachLines)
			indirect = indirect[:maxIndirectReachLines]
		}
		for _, l := range indirect {
			fmt.Fprintln(w, l)
		}
	}
	return nil
}

// maxIndirectReachLines bounds the indirect-reach list for the same reason
// maxRefusalLines bounds the refusal list: a large team (or a hostile one,
// via a large declared agent count) must not make this view's own output
// unbounded.
const maxIndirectReachLines = 40

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// nodeGlyph mirrors internal/graph's own unexported glyphFor: the same four
// marks (agent, domain, store key, secret), for the legend rather than the
// canvas.
func nodeGlyph(n graph.TerminalNode) string {
	if n.Node.Kind == graph.NodeAgent {
		return "●"
	}
	switch n.ResourceKind {
	case graph.Domain:
		return "◆"
	case graph.StoreKey:
		return "■"
	case graph.Secret:
		return "▲"
	default:
		return "□"
	}
}

// nodeLabelWidth is how many runes of an identifier nodeLabel shows before
// clamping with an ellipsis. A store key is bounded at 1 KiB
// (internal/team.MaxKeyBytes) and an agent name at 64 characters
// (internal/team.ValidAgentName) — both far wider than one legend line
// should ever spend on a single value, and both at least partly a config
// author's or a guest's choice.
const nodeLabelWidth = 60

// clampWidth truncates s to at most max runes, marking that it did with a
// trailing "…" — the same truncate-with-ellipsis shape host/watch.go's fit
// uses for a fixed-width table cell, applied here to a value with no cell to
// pad into. Always called after proto.SafeText, never before: SafeText's
// quoting can grow a string with a control byte in it, and clamping first
// would let that growth push the final line past max anyway.
func clampWidth(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}

// nodeLabel names one legend entry. Every value here can be guest-influenced
// only through host-authored config today (an agent name, a domain, a store
// rule's own name) — proto.SafeText is applied anyway, with no exception,
// per P7-7's own rule, and clamped afterward so a long one cannot wrap the
// line across several rows on its own.
func nodeLabel(n graph.TerminalNode) string {
	if n.Node.Kind == graph.NodeAgent {
		s := clampWidth(proto.SafeText(n.Node.ID), nodeLabelWidth)
		if n.Group != "" {
			s += " (fork group " + clampWidth(proto.SafeText(n.Group), nodeLabelWidth) + ")"
		}
		return s
	}
	return clampWidth(proto.SafeText(n.Node.ID), nodeLabelWidth) + " (" + n.ResourceKind.String() + ")"
}

// edgeArrow labels one agent-resource access. Write is meaningless for a
// Domain or a Secret (internal/graph's own Access doc comment), so those
// read the same regardless of which EdgeKind the layout gave the edge —
// "reaches"/"uses" rather than an accidental "reads" that would otherwise
// imply the pair the layout never actually distinguished for these two
// kinds. A StoreKey is the one resource where read and write are real,
// different facts, so that is where the distinction is shown.
func edgeArrow(k graph.EdgeKind, kind graph.ResourceKind) string {
	switch kind {
	case graph.Domain:
		return "reaches"
	case graph.Secret:
		return "uses"
	}
	if k == graph.EdgeWrite {
		return "writes"
	}
	return "reads"
}

func portList(ports []int) string {
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ", ")
}

// maxRefusalLines bounds how many refused attempts printRecentRefusals shows
// — bounded, and saying so when it truncates, the same rule internal/digest
// already applies to its own counters (MaxDistinctKeys) and for the same
// reason: a peer or a store key named in a refusal is at least partly a
// guest's choice, and a hostile session looping team_send at an invented
// recipient must not be able to make this view's own output unbounded.
const maxRefusalLines = 20

// refusalLine returns the display line for one refused team.refused,
// team.store or team.spawn event: the fix line internal/denial's catalog
// already writes for it when the recorded event carries every field that
// fix line needs, or — for a reason the catalog has no entry for at all, or
// whose full message needs a value the recorded event does not carry (a
// refused team.spawn records only the spawner's name and the reason, never
// the image or the live/max counts the in-process error saw) — a plain,
// honest sentence naming what happened and, where one exists, the fix.
//
// Every refusal reason team.refused/team.store/team.spawn can carry is
// covered here except two, deliberately: team.store's "no_such_key" is an
// absence, not a refusal — docs/teams.md's own words, "Absence is not a
// refusal and must not look like one" — and team.spawn's despawn-side
// "not_a_spawned_worker" is an internal condition nobody watching a team's
// policy file can act on. ok is false for both of those, for a delivered
// event, and for anything this function does not recognise.
func refusalLine(e recorder.Event) (line string, ok bool) {
	agent := clampWidth(proto.SafeText(e.Agent), nodeLabelWidth)
	peer := clampWidth(proto.SafeText(e.Peer), nodeLabelWidth)
	switch e.Type {
	case recorder.TypeTeamRefused:
		switch e.Reason {
		case "no_edge":
			return denial.TeamEdge.Render(denial.V{"from": agent, "to": peer}), true
		case "no_such_agent":
			return fmt.Sprintf("%s addressed %s, who is not in this team [team.refused]\n"+
				"    check the name, or add %s to the team file", agent, peer, peer), true
		case "missing_correlation":
			return fmt.Sprintf("%s's team_reply carried no correlate tag [team.refused]\n"+
				"    team_reply needs the correlate value team_recv returned", agent), true
		case "unknown_correlation":
			return fmt.Sprintf("%s's team_reply matched no outstanding question [team.refused]\n"+
				"    the question it names has already been answered, or was never asked", agent), true
		}
	case recorder.TypeTeamStore:
		if e.Outcome == "delivered" {
			return "", false
		}
		verb := "read"
		if e.Kind == "put" || e.Kind == "delete" {
			verb = "write"
		}
		switch e.Reason {
		case "denied":
			return denial.TeamStore.Render(denial.V{"agent": agent, "verb": verb, "key": peer}), true
		case "key_too_long":
			return fmt.Sprintf("%s tried a store key over %d bytes [team.store]\n"+
				"    shorten the key — a store key may be at most %d bytes",
				agent, team.MaxKeyBytes, team.MaxKeyBytes), true
		case "value_too_large":
			return fmt.Sprintf("%s tried to write more than %d bytes to one store key [team.store]\n"+
				"    write a smaller value, or split it across more than one key",
				agent, team.MaxValueBytes), true
		case "too_many_keys":
			return fmt.Sprintf("%s's team has reached its %d-key store limit [team.store]\n"+
				"    write an empty value to a key nobody needs, to free one",
				agent, team.MaxStoreKeys), true
		case "store_full":
			return fmt.Sprintf("%s's team has reached its %d-byte store limit [team.store]\n"+
				"    write an empty value to a key nobody needs, to free space",
				agent, team.MaxStoreBytes), true
		}
	case recorder.TypeTeamSpawn:
		if e.Kind != "spawn" || e.Outcome == "delivered" {
			return "", false
		}
		switch e.Reason {
		case "no_spawn_budget":
			return denial.TeamSpawnNone.Render(denial.V{"agent": agent}), true
		case "budget_exhausted":
			return fmt.Sprintf("%s already has as many spawned workers as its budget allows [team.spawn]\n"+
				"    raise max in [team.agent.spawn] for %s in the team file, or let one finish",
				agent, agent), true
		case "image_not_permitted":
			return fmt.Sprintf("%s tried to spawn an image its budget does not permit [team.spawn]\n"+
				"    add the image to [team.agent.spawn] images for %s in the team file",
				agent, agent), true
		case "name_taken":
			return fmt.Sprintf("%s's spawned worker %s collided with an existing agent name [team.spawn]\n"+
				"    rename the declared agent %s in the team file", agent, peer, peer), true
		}
	}
	return "", false
}

// printRecentRefusals lists every refusal refusalLine recognises, recorded
// so far, each with the fix line it carries — the view answers "now what"
// and not only "what" (P7-7).
func printRecentRefusals(w io.Writer, d *digest.Digest) {
	var lines []string
	for _, entry := range d.Timeline {
		if l, ok := refusalLine(entry.Event); ok {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "refused since boot")
	if len(lines) > maxRefusalLines {
		fmt.Fprintf(w, "  … %d earlier refusal(s) not shown\n", len(lines)-maxRefusalLines)
		lines = lines[len(lines)-maxRefusalLines:]
	}
	for _, l := range lines {
		for _, ln := range strings.Split(l, "\n") {
			fmt.Fprintln(w, "  "+ln)
		}
	}
}
