package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/graph"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// This file is P7-8's own reading of P7-2/P7-3's declaration
// (session.policy, team.topology) and P7-6's layout engine
// (internal/graph): the run map, the agent sheets, the reach matrix and the
// store panel above the report's existing lane timeline.
//
// Security-critical constraint, carried from the task text into every
// function below: adversary strings — an agent name, a domain, a store key,
// a secret's name or host — reach element text content only. Every
// coordinate this file computes is a plain Go number, taken from
// internal/graph.SVG, which itself never carries a string a caller could
// have made adversarial (P7-6's own package doc). Nothing here builds an
// SVG attribute by formatting a guest-influenced string into it; the two
// string-valued attributes the drawing uses at all — the fixed "class"
// vocabulary chosen from a closed Go switch, and nothing else — never carry
// anything a record's own guest-facing fields could have put there.

// nodeRadius and nodeHalf size the four node shapes the run map draws,
// mirroring internal/graph/terminal.go's own glyph choice per kind (●
// agent, ◆ domain, ■ store key, ▲ secret) so the two backends never
// disagree about which shape means what.
const (
	nodeRadius = 16.0
	nodeHalf   = 15.0
	labelGap   = 13.0
)

// RunMapView is the declared team topology (plus any runtime spawn — see
// collectAgents), drawn as an SVG the template renders directly from plain
// numeric and closed-vocabulary fields. Nil when the session opened no team.
type RunMapView struct {
	Width, Height                                               float64
	Nodes                                                       []MapNode
	Edges                                                       []MapEdge
	AgentCount, EdgeCount, DomainCount, StoreCount, SecretCount int
}

// MapNode is one placed node. Kind is one of "agent", "domain", "store",
// "secret" — a fixed vocabulary this file assigns, never a value read off
// the record. Points is precomputed, comma/space-joined coordinates for a
// non-circle shape's <polygon>, always built from float64 math — see the
// package comment on why that is not the same thing as building a string
// from a guest-influenced value.
type MapNode struct {
	CX, CY float64
	LX, LY float64
	R      float64 // agent nodes only — the <circle>'s radius
	Kind   string
	Label  string // agent name, domain, store key or "name@host" — guest-influenced, rendered in <text> content only
	Sub    string // fork-template group, agent nodes only
	Points string // non-agent nodes only — a <polygon>'s points attribute
}

// MapEdge is one routed edge. Kind is "message" (a declared team.edge or a
// delivered team.spawn), "read" or "write" (a resolved store/domain/secret
// access) — again a fixed vocabulary, never guest data.
type MapEdge struct {
	Kind   string
	Points string
	Title  string // e.g. "master → worker-1" — guest-influenced, rendered in a nested <title> only
}

// AgentSheetView is one machine's declared policy (session.policy),
// rendered field for field. HasPolicy is false when no session.policy was
// ever absorbed for this machine — a chain that predates P7-2, or one that
// ended before the event landed — and the sheet says so rather than
// rendering a page of zeroes that would read as "this machine was granted
// nothing".
type AgentSheetView struct {
	Name, Sandbox, Group, SpawnedBy string
	HasPolicy                       bool

	Vcpus, MemMiB, CPUQuota    int
	Disk, Scratch              string // pre-formatted via HumanBytes; "" when not applicable
	NetRxMbps, NetTxMbps       int
	DiskIOPS, DiskMbps         int
	MaxRuntime, IdleTimeout    string // pre-formatted duration; "" when unbudgeted
	Allow                      []string
	Ports                      []int
	Secrets                    []AgentSecretView
	Workspace                  string
	Plugins, Forwards          []string
	RootfsSHA256, KernelSHA256 string
	Tools                      []string
	ParentSession, Traceparent string
}

// AgentSecretView is one bound credential, named but never valued — the
// same discipline session.policy itself keeps (docs/policy-record.md §8.1).
type AgentSecretView struct{ Name, Host, Path string }

// ReachMatrixView is graph.TransitiveClosure read out as a table: what a
// compromised agent's output could actually reach, over declared edges and
// shared store keys. Nil when there are fewer than two agents to relate.
type ReachMatrixView struct {
	Agents []string
	Rows   []ReachRow
}

// ReachRow is one agent's row: its hop count to every other agent, in the
// same column order as ReachMatrixView.Agents.
type ReachRow struct {
	From  string
	Cells []ReachCell
}

// ReachCell is one (from, to) pair. Exactly one of Self, Reaches or neither
// is true; when neither is, CoTenant says whether the two still share a
// domain or a secret this product cannot rule out as an out-of-band channel
// (internal/graph's own package doc) — text-distinguished, not colour-only.
type ReachCell struct {
	Self     bool
	Reaches  bool
	Hops     int
	CoTenant bool
}

// StorePanelView is the team's declared store ACLs beside what was actually
// touched. Nil when the team never declared a store rule and nothing was
// ever recorded against one.
type StorePanelView struct {
	Rules     []StoreRuleView
	Keys      []StoreKeyActivityView
	Truncated bool
}

// StoreRuleView is one [[team.store.key]] rule, exactly as team.topology
// recorded it — name (which may itself be a glob), read list, write list.
type StoreRuleView struct {
	Name        string
	Read, Write []string
}

// StoreKeyActivityView is one concrete key's observed activity, plus which
// rule (if any) this file resolved as covering it.
type StoreKeyActivityView struct {
	Key                         string
	Gets, Puts, Deletes, Denied int
	Bytes                       int64
	Covered                     string
}

// RunSection bundles everything P7-8 adds, built once from the fold so the
// map, the sheets, the matrix and the store panel can never disagree about
// which agents exist — the discipline P7-1 already applies to the flat
// timeline and the lane view.
type RunSection struct {
	Map    *RunMapView
	Agents []AgentSheetView
	Reach  *ReachMatrixView
	Store  *StorePanelView
	// Note explains, in plain words, why the map or the matrix could not be
	// drawn. Set only on the one failure path possible here: an
	// inconsistent chain (an edge or an access naming an agent this file
	// never otherwise learned about) — never merely because a team is
	// small; one agent with no edges is a valid, empty map.
	Note string
}

// buildRunSection is internal/report's one reading of session.policy and
// team.topology. It never touches the raw chain again — everything it
// needs is already on the fold (digest.Digest), the same way fillSummary,
// timelineRows and buildLanes only ever read the fold too.
func buildRunSection(d *digest.Digest) RunSection {
	sec := RunSection{Agents: buildAgentSheets(d)}
	if d.Topology == nil {
		return sec
	}

	agents := collectAgents(d)
	in := buildGraphInput(d, agents)

	if m, errText := buildRunMap(in); errText != "" {
		sec.Note = "the declared topology could not be drawn: " + errText
	} else {
		sec.Map = m
	}
	if r, errText := buildReachMatrix(in); errText != "" {
		if sec.Note == "" {
			sec.Note = "the reach matrix could not be computed: " + errText
		}
	} else {
		sec.Reach = r
	}
	sec.Store = buildStorePanel(d)
	return sec
}

// runAgent is one node buildRunSection knows about, before it is turned
// into graph.Agent / AgentSheetView: a declared team.topology member, or a
// runtime-spawned worker (team.topology's own doc says a spawn's later
// arrival is covered by team.spawn alone, not a second topology write).
type runAgent struct {
	Name, Sandbox, Group, SpawnedBy string
	Declared                        bool
}

// collectAgents is the one place the report decides which machines exist
// for the run section: every agent team.topology declared, plus every
// worker a delivered team.spawn actually attached — the union that makes
// the acceptance test's "six agents, five declared edges" true for a team
// that declared five and spawned a sixth mid-run. A declared agent is never
// re-labelled "spawned" even if a spawn event happens to name it again.
func collectAgents(d *digest.Digest) []runAgent {
	var order []string
	seen := map[string]*runAgent{}
	get := func(name string) *runAgent {
		if a, ok := seen[name]; ok {
			return a
		}
		a := &runAgent{Name: name}
		seen[name] = a
		order = append(order, name)
		return a
	}

	if d.Topology != nil {
		for _, ea := range d.Topology.Agents {
			a := get(ea.Name)
			a.Sandbox, a.Group, a.Declared = ea.Sandbox, ea.Group, true
		}
	}
	for _, en := range d.Timeline {
		if en.Type != recorder.TypeTeamSpawn || en.Refused {
			continue
		}
		get(en.Agent)
		peer := get(en.Peer)
		if !peer.Declared && peer.SpawnedBy == "" {
			peer.SpawnedBy = en.Agent
		}
	}
	// Belt and suspenders against a malformed or hostile chain: any agent
	// this fold learned a declared policy for, but that neither
	// team.topology nor a delivered team.spawn ever named, still gets a
	// node — silently dropping its access would understate what the team
	// can reach, the one direction internal/graph's own package doc says
	// this must never do.
	for _, name := range d.AgentOrder {
		if a := d.Agents[name]; a != nil && a.Policy != nil {
			get(name)
		}
	}

	out := make([]runAgent, len(order))
	for i, n := range order {
		out[i] = *seen[n]
	}
	return out
}

// agentPolicy looks up name's session.policy on the fold, or nil when none
// was ever absorbed for it.
func agentPolicy(d *digest.Digest, name string) *recorder.Event {
	if a, ok := d.Agents[name]; ok && a.Policy != nil {
		return a.Policy
	}
	return nil
}

// buildGraphInput turns the fold's own view of the team into
// internal/graph's Input: agents, declared-plus-spawned edges, and every
// domain, secret and store key an agent's own policy or the team's store
// rules grant it — resource IDs are deduplicated here, since
// graph.normalize errors on a duplicate rather than merging it.
func buildGraphInput(d *digest.Digest, agents []runAgent) graph.Input {
	in := graph.Input{}
	for _, a := range agents {
		in.Agents = append(in.Agents, graph.Agent{ID: graph.AgentID(a.Name), Group: a.Group})
	}
	in.Edges = collectEdges(d, agents)

	resSeen := map[graph.ResourceID]bool{}
	addRes := func(id string, kind graph.ResourceKind) graph.ResourceID {
		rid := graph.ResourceID(id)
		if !resSeen[rid] {
			resSeen[rid] = true
			in.Resources = append(in.Resources, graph.Resource{ID: rid, Kind: kind})
		}
		return rid
	}
	accSeen := map[graph.Access]bool{}
	addAccess := func(agent string, rid graph.ResourceID, write bool) {
		a := graph.Access{Agent: graph.AgentID(agent), Resource: rid, Write: write}
		if !accSeen[a] {
			accSeen[a] = true
			in.Access = append(in.Access, a)
		}
	}

	for _, a := range agents {
		pol := agentPolicy(d, a.Name)
		if pol == nil {
			continue
		}
		for _, host := range pol.Allow {
			addAccess(a.Name, addRes(host, graph.Domain), false)
		}
		for _, s := range pol.Secrets {
			addAccess(a.Name, addRes(s.Name+"@"+s.Host, graph.Secret), false)
		}
	}

	if d.Topology != nil {
		collectStoreAccess(d, agents, addRes, addAccess)
	}

	return in
}

// collectEdges is the "declared plus spawned" edge list: every pair
// team.topology's own Edges already expanded (host/teamplan.go's
// "from -> to" text, reused verbatim rather than re-deriving the topology a
// second time), plus one edge per delivered team.spawn — spawner to
// spawned — since a spawn's arrival is covered by that event alone
// (docs/policy-record.md §3), not a second team.topology write.
func collectEdges(d *digest.Digest, agents []runAgent) []graph.Edge {
	known := make(map[string]bool, len(agents))
	for _, a := range agents {
		known[a.Name] = true
	}
	seen := map[graph.Edge]bool{}
	var edges []graph.Edge
	add := func(from, to string) {
		if from == "" || to == "" || from == to || !known[from] || !known[to] {
			return
		}
		e := graph.Edge{From: graph.AgentID(from), To: graph.AgentID(to)}
		if seen[e] {
			return
		}
		seen[e] = true
		edges = append(edges, e)
	}

	if d.Topology != nil {
		for _, s := range d.Topology.Edges {
			if from, to, ok := strings.Cut(s, " -> "); ok {
				add(from, to)
			}
		}
	}
	for _, en := range d.Timeline {
		if en.Type == recorder.TypeTeamSpawn && !en.Refused {
			add(en.Agent, en.Peer)
		}
	}
	return edges
}

// collectStoreAccess resolves every store key this report can name a
// concrete owner for into graph Resource/Access entries: every key
// team.topology declared a literal (non-glob) rule for, and every key the
// fold actually observed an access to (Digest.Store) — the union covers a
// rule declared and never used, and a key used under no rule at all. A
// rule whose Name is itself a glob with no concrete key ever observed draws
// nothing: a pattern is not a resource a compromised agent's output can
// reach, only the concrete keys it matches are.
//
// Resolution mirrors internal/team/store.go's own `may`: rules are tried in
// declared order and the first whose Name matches the key decides; a key no
// rule matches is readable and writable by the whole team by default
// (internal/team/store.go's own comment, and internal/graph's package doc
// names this exact caller obligation) — synthesized here as full team
// access, or the reach matrix understates what an unruled key's readers and
// writers can actually reach, which is the one direction this view must
// never be wrong in.
func collectStoreAccess(d *digest.Digest, agents []runAgent,
	addRes func(string, graph.ResourceKind) graph.ResourceID,
	addAccess func(string, graph.ResourceID, bool)) {

	rules := d.Topology.StoreKeys
	keySet := map[string]bool{}
	for _, k := range d.StoreOrder {
		keySet[k] = true
	}
	for _, r := range rules {
		if !strings.HasSuffix(r.Name, "*") {
			keySet[r.Name] = true
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		rid := addRes(key, graph.StoreKey)
		rule, matched := matchStoreRule(rules, key)
		if !matched {
			for _, a := range agents {
				addAccess(a.Name, rid, false)
				addAccess(a.Name, rid, true)
			}
			continue
		}
		for _, a := range agents {
			if matchesAny(rule.Read, a.Name) {
				addAccess(a.Name, rid, false)
			}
			if matchesAny(rule.Write, a.Name) {
				addAccess(a.Name, rid, true)
			}
		}
	}
}

func matchStoreRule(rules []recorder.EvStoreKey, key string) (recorder.EvStoreKey, bool) {
	for _, r := range rules {
		if globMatch(r.Name, key) {
			return r, true
		}
	}
	return recorder.EvStoreKey{}, false
}

func matchesAny(list []string, name string) bool {
	for _, who := range list {
		if who == "*" || globMatch(who, name) {
			return true
		}
	}
	return false
}

// globMatch mirrors internal/team/store.go's own globMatch exactly: a
// trailing "*" is a prefix match, and nothing else is special.
// Reimplemented rather than imported — the original is unexported, and this
// package's whole reason to exist is reading the record after the fact, not
// reaching into internal/team's live store.
func globMatch(pattern, s string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(s, prefix)
	}
	return pattern == s
}

// buildRunMap lays in out with internal/graph.Layout and scales it to
// pixels with internal/graph.SVG — the exact same two calls
// `kelyfos team graph` makes for its own drawing (P7-6, P7-7), so the two
// never disagree about a topology they compute from the same Input. The
// error string it can return is internal/graph's own — it may itself embed
// a guest-influenced agent or resource id — and is meant for RunSection.Note,
// which the template renders as ordinary escaped text, never as markup.
func buildRunMap(in graph.Input) (*RunMapView, string) {
	if len(in.Agents) == 0 {
		return nil, ""
	}
	placement, err := graph.Layout(in)
	if err != nil {
		return nil, err.Error()
	}
	svg := graph.SVG(placement, graph.DefaultSVGOptions())

	v := &RunMapView{Width: svg.Width, Height: svg.Height}
	for _, n := range svg.Nodes {
		mn := MapNode{CX: n.Pos.X, CY: n.Pos.Y, Label: n.Node.ID}
		if n.Node.Kind == graph.NodeAgent {
			mn.Kind, mn.Sub, mn.R = "agent", n.Group, nodeRadius
			mn.LX, mn.LY = n.Pos.X, n.Pos.Y+nodeRadius+labelGap
			v.AgentCount++
		} else {
			switch n.ResourceKind {
			case graph.Domain:
				mn.Kind = "domain"
				v.DomainCount++
			case graph.StoreKey:
				mn.Kind = "store"
				v.StoreCount++
			case graph.Secret:
				mn.Kind = "secret"
				v.SecretCount++
			}
			mn.Points = shapePoints(mn.Kind, n.Pos.X, n.Pos.Y)
			mn.LX, mn.LY = n.Pos.X, n.Pos.Y+nodeHalf+labelGap
		}
		v.Nodes = append(v.Nodes, mn)
	}
	for _, e := range svg.Edges {
		me := MapEdge{Points: pointsAttr(e.Path)}
		switch e.Kind {
		case graph.EdgeMessage:
			me.Kind = "message"
			me.Title = string(e.From.ID) + " → " + string(e.To.ID)
			v.EdgeCount++
		case graph.EdgeRead:
			me.Kind = "read"
			me.Title = string(e.From.ID) + " reads " + string(e.To.ID)
		case graph.EdgeWrite:
			me.Kind = "write"
			me.Title = string(e.From.ID) + " writes " + string(e.To.ID)
		}
		v.Edges = append(v.Edges, me)
	}
	return v, ""
}

// shapePoints returns a <polygon>'s numeric points attribute for a
// resource's kind — diamond for a domain, square for a store key, triangle
// for a secret — mirroring internal/graph/terminal.go's own glyph choice
// (◆ ■ ▲). Every coordinate is float64 arithmetic on cx/cy; nothing here
// ever formats a string value into the result.
func shapePoints(kind string, cx, cy float64) string {
	switch kind {
	case "domain":
		return pts(cx, cy-nodeHalf, cx+nodeHalf, cy, cx, cy+nodeHalf, cx-nodeHalf, cy)
	case "store":
		return pts(cx-nodeHalf, cy-nodeHalf, cx+nodeHalf, cy-nodeHalf, cx+nodeHalf, cy+nodeHalf, cx-nodeHalf, cy+nodeHalf)
	case "secret":
		return pts(cx, cy-nodeHalf, cx+nodeHalf, cy+nodeHalf, cx-nodeHalf, cy+nodeHalf)
	default:
		return ""
	}
}

func pts(coords ...float64) string {
	parts := make([]string, 0, len(coords)/2)
	for i := 0; i+1 < len(coords); i += 2 {
		parts = append(parts, f1(coords[i])+","+f1(coords[i+1]))
	}
	return strings.Join(parts, " ")
}

func pointsAttr(path []graph.SVGPoint) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = f1(p.X) + "," + f1(p.Y)
	}
	return strings.Join(parts, " ")
}

// f1 formats a coordinate to one decimal place — the only shape a number in
// this file's SVG output ever takes: digits, an optional leading "-" and a
// single ".", nothing else.
func f1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// buildReachMatrix runs internal/graph.TransitiveClosure over the same
// Input the map drew, so the picture and the matrix never disagree about
// which agents exist either.
func buildReachMatrix(in graph.Input) (*ReachMatrixView, string) {
	if len(in.Agents) < 2 {
		return nil, ""
	}
	closure, err := graph.TransitiveClosure(in)
	if err != nil {
		return nil, err.Error()
	}
	v := &ReachMatrixView{Agents: make([]string, len(closure.Agents))}
	for i, a := range closure.Agents {
		v.Agents[i] = string(a)
	}
	for _, from := range closure.Agents {
		row := ReachRow{From: string(from)}
		for _, to := range closure.Agents {
			var c ReachCell
			if from == to {
				c.Self = true
			} else {
				hops, reachable := closure.HopsBetween(from, to)
				c.Reaches, c.Hops = reachable, hops
				if !reachable && len(closure.SharedResources(from, to)) > 0 {
					c.CoTenant = true
				}
			}
			row.Cells = append(row.Cells, c)
		}
		v.Rows = append(v.Rows, row)
	}
	return v, ""
}

// buildAgentSheets is every machine's declared policy: one sheet per
// collectAgents entry for a team, or exactly one sheet for a single,
// non-team machine's own agentless session.policy.
func buildAgentSheets(d *digest.Digest) []AgentSheetView {
	if d.Topology != nil {
		agents := collectAgents(d)
		sheets := make([]AgentSheetView, len(agents))
		for i, a := range agents {
			sheets[i] = policySheet(a.Name, a.Sandbox, a.Group, a.SpawnedBy, agentPolicy(d, a.Name))
		}
		return sheets
	}
	if d.Policy != nil {
		return []AgentSheetView{policySheet("", "", "", "", d.Policy)}
	}
	return nil
}

// policySheet turns one session.policy event into its rendered form. e is
// nil for a machine this fold never absorbed a policy for, in which case
// every field but the identity ones stays zero and HasPolicy says why.
func policySheet(name, sandbox, group, spawnedBy string, e *recorder.Event) AgentSheetView {
	v := AgentSheetView{Name: name, Sandbox: sandbox, Group: group, SpawnedBy: spawnedBy}
	if e == nil {
		return v
	}
	v.HasPolicy = true
	v.Vcpus, v.MemMiB, v.CPUQuota = e.VcpuCount, e.MemMiB, e.CPUQuota
	if e.DiskBytes > 0 {
		v.Disk = HumanBytes(e.DiskBytes)
	}
	if e.ScratchBytes > 0 {
		v.Scratch = HumanBytes(e.ScratchBytes)
	}
	v.NetRxMbps, v.NetTxMbps = e.NetMbpsRx, e.NetMbpsTx
	v.DiskIOPS, v.DiskMbps = e.DiskIOPS, e.DiskMbps
	if e.MaxRuntimeMS > 0 {
		v.MaxRuntime = (time.Duration(e.MaxRuntimeMS) * time.Millisecond).String()
	}
	if e.IdleTimeoutMS > 0 {
		v.IdleTimeout = (time.Duration(e.IdleTimeoutMS) * time.Millisecond).String()
	}
	v.Allow, v.Ports = e.Allow, e.Ports
	for _, s := range e.Secrets {
		v.Secrets = append(v.Secrets, AgentSecretView{s.Name, s.Host, s.Path})
	}
	v.Workspace = e.Workspace
	v.Plugins, v.Forwards = e.Plugins, e.Forwards
	v.RootfsSHA256, v.KernelSHA256 = e.RootfsSHA256, e.KernelSHA256
	v.Tools = e.Tools
	v.ParentSession, v.Traceparent = e.ParentSession, e.Traceparent
	return v
}

// buildStorePanel lists the team's declared ACLs beside what was actually
// touched. Nil when the team declared no store rule and nothing was ever
// recorded against one, so a team with the store off entirely does not grow
// an empty section.
func buildStorePanel(d *digest.Digest) *StorePanelView {
	if d.Topology == nil {
		return nil
	}
	rules := d.Topology.StoreKeys
	if len(rules) == 0 && len(d.Store) == 0 {
		return nil
	}
	v := &StorePanelView{Truncated: d.StoreTruncated}
	for _, r := range rules {
		v.Rules = append(v.Rules, StoreRuleView{Name: r.Name, Read: r.Read, Write: r.Write})
	}
	for _, key := range d.StoreOrder {
		sk := d.Store[key]
		covered := "team-wide (no rule matches)"
		if rule, ok := matchStoreRule(rules, key); ok {
			covered = "rule " + rule.Name
		}
		v.Keys = append(v.Keys, StoreKeyActivityView{
			Key: key, Gets: sk.Gets, Puts: sk.Puts, Deletes: sk.Deletes, Denied: sk.Denied,
			Bytes: sk.Bytes, Covered: covered,
		})
	}
	return v
}
