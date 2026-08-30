package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/ikapa-dev/kelyfos/internal/digest"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// The resources lane is the one part of `kelyfos watch` that does not come from
// the flight recorder, so it is the part worth pinning: what it says, and that
// it always says what a number was measured against.
func TestResourceLaneShowsUsageAgainstItsCaps(t *testing.T) {
	now := time.Now()
	m := &watchModel{session: "abcd1234"}

	// Before any sample: no numbers, and no pretending.
	if got := m.resourceLane(); !strings.Contains(got, "waiting for the first sample") {
		t.Errorf("empty lane = %q", got)
	}

	// One sample is a reading, not a rate: CPU stays blank until there are two.
	first := usageMsg{
		usage: sandbox.Usage{CPUSeconds: 1, RSSKiB: 100 << 10},
		state: sandbox.State{VcpuCount: 2, MemMiB: 512, CPUQuota: 60},
		at:    now,
	}
	m.Update(first)
	if got := m.resourceLane(); !strings.Contains(got, "cpu   —") {
		t.Errorf("a single sample reported a rate: %q", got)
	}

	// Two samples a second apart, half a CPU-second used: 50%.
	m.Update(usageMsg{
		usage: sandbox.Usage{CPUSeconds: 1.5, RSSKiB: 122 << 10, DiskWriteBytes: 40 << 20,
			NetInBytes: 3 << 20, NetOutBytes: 1 << 10},
		state: sandbox.State{VcpuCount: 2, MemMiB: 512, CPUQuota: 60, NetMbpsRx: 10},
		at:    now.Add(time.Second),
	})
	got := m.resourceLane()
	for _, want := range []string{
		"cpu  50.0% of 60% quota", // the rate, and the cap it is measured against
		"mem 122 MiB (VMM), machine 512 MiB",
		"net 3.0 MiB in / 1 KiB out (cap 10/0 Mbps)",
		"disk 40.0 MiB written",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lane %q\n  is missing %q", got, want)
		}
	}
}

// Once the sandbox has stopped there is nothing left to sample, and the lane
// shows the receipt the recorder kept instead.
func TestResourceLaneFallsBackToTheRecordedReceipt(t *testing.T) {
	m := &watchModel{session: "abcd1234"}
	m.absorb(recorder.Event{
		Type: recorder.TypeResourceSummary, CPUSeconds: 1.68, PeakRSSKiB: 122 << 10,
		MemMiB: 512, CPUQuota: 80, DiskWriteBytes: 40 << 20,
	})
	got := m.resourceLane()
	for _, want := range []string{
		"final ·", "1.68 CPU-seconds", "quota 80% of one core",
		"peak RSS 122 MiB", "machine 512 MiB", "disk 40.0 MiB written",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("receipt lane %q\n  is missing %q", got, want)
		}
	}
}

// teamEvents is a small team's chain: two agents doing work, one message, one
// refusal, one store denial. Built as events rather than driven through a real
// team, because what is under test is the view.
func teamEvents() []recorder.Event {
	code0, code3 := 0, 3
	return []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-23T10:00:00.000Z", Arch: "aarch64"},
		{Type: recorder.TypeCommandStart, TS: "2026-08-23T10:00:01.000Z", Agent: "master",
			Cmd: []string{"echo", "assembling"}, Call: "c1", Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-23T10:00:01.100Z", Agent: "master",
			Call: "c1", Code: &code0},
		{Type: recorder.TypeCommandStart, TS: "2026-08-23T10:00:02.000Z", Agent: "worker-1",
			Cmd: []string{"scan"}, Call: "c2", Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-23T10:00:02.100Z", Agent: "worker-1",
			Call: "c2", Code: &code3},
		{Type: recorder.TypeTeamMessage, TS: "2026-08-23T10:00:03.000Z", Agent: "master",
			Peer: "worker-1", Kind: "send", Bytes: 10},
		{Type: recorder.TypeTeamRefused, TS: "2026-08-23T10:00:04.000Z", Agent: "worker-1",
			Peer: "worker-2", Kind: "send", Bytes: 4, Reason: "no_edge"},
		{Type: recorder.TypeTeamStore, TS: "2026-08-23T10:00:05.000Z", Agent: "worker-1",
			Peer: "findings/a", Kind: "get", Outcome: "refused", Reason: "denied"},
	}
}

func teamModel() *watchModel {
	m := &watchModel{session: "team1234", started: time.Now()}
	for _, e := range teamEvents() {
		m.absorb(e)
	}
	return m
}

// A session that carries agents is a team, and nothing had to be asked or
// flagged for the view to know it. Lane order is boot order.
func TestATeamSessionBecomesLanesWithoutBeingTold(t *testing.T) {
	m := teamModel()
	if got := strings.Join(m.order, " "); got != "master worker-1" {
		t.Errorf("lanes = %q, want boot order", got)
	}
	// An event that names no agent stays out of every lane — it belongs to the
	// team, not to whichever agent happens to be first.
	if len(m.lines) == 0 {
		t.Error("the session-wide event went into a lane")
	}
	if m.agentCounters("master").Commands != 1 || m.agentCounters("worker-1").Failed != 1 {
		t.Errorf("counters landed in the wrong lane: %+v %+v",
			m.agentCounters("master"), m.agentCounters("worker-1"))
	}
}

// A message belongs to two agents, so it belongs in neither lane: it goes in
// the ticker, with both ends and the direction.
func TestMessagesGoToTheTickerAndNotIntoALane(t *testing.T) {
	m := teamModel()
	if m.d.Messages != 1 || m.d.AllRefusals() != 2 {
		t.Errorf("messages=%d refused=%d, want 1 and 2 (a refused send and a denied store)",
			m.d.Messages, m.d.AllRefusals())
	}
	flow := strings.Join(m.flow, "\n")
	for _, want := range []string{"master → worker-1", "REFUSED", "worker-1 → worker-2", "no_edge"} {
		if !strings.Contains(flow, want) {
			t.Errorf("the ticker is missing %q:\n%s", want, flow)
		}
	}
	// The store access itself is one agent's doing, so it is in that lane.
	if !strings.Contains(strings.Join(m.lanes["worker-1"].lines, "\n"), "findings/a") {
		t.Error("the store access is not in the lane of the agent that made it")
	}
}

// Columns that are only usually the same width are not columns.
func TestLanesAreExactlyTheSameWidth(t *testing.T) {
	m := teamModel()
	block := m.laneBlock(m.lanes["worker-1"], 24, 6)
	if len(block) != 8 {
		t.Fatalf("lane block has %d lines, want laneH+2", len(block))
	}
	for i, line := range block {
		if w := lipgloss.Width(line); w != 24 {
			t.Errorf("line %d is %d columns wide, want 24: %q", i, w, line)
		}
	}
}

// Below a readable width the view stops pretending and says why. Eight columns
// per agent is not a team view, it is a puzzle.
func TestANarrowTerminalFallsBackToOneColumnAndSaysSo(t *testing.T) {
	m := teamModel()
	narrow := m.teamView(40, 30)
	if !strings.Contains(narrow, "showing one column instead") {
		t.Errorf("a 40-column terminal did not fall back:\n%s", narrow)
	}
	for _, want := range []string{"[master]", "[worker-1]"} {
		if !strings.Contains(narrow, want) {
			t.Errorf("the merged column does not say which agent %q came from", want)
		}
	}
	wide := m.teamView(160, 30)
	if strings.Contains(wide, "showing one column instead") {
		t.Error("a 160-column terminal fell back unnecessarily")
	}
	if !strings.Contains(wide, "master") || !strings.Contains(wide, "worker-1") {
		t.Error("the wide view is missing a lane heading")
	}
}

// The collective cap is read from the parent cgroup the cap is written on, so
// the number and the limit cannot be about different things.
func TestTheTeamBudgetLineSaysWhatWasSpentAgainstWhat(t *testing.T) {
	m := teamModel()
	if got := m.teamBudgetLine(); !strings.Contains(got, "none declared") {
		t.Errorf("a team with no budget claimed one: %q", got)
	}
	m.Update(teamUsageMsg{
		cgroup: "/sys/fs/cgroup/kelyfos-team-x",
		quota:  200, cpuSeconds: 45.5, throttled: 107.6, at: time.Now(),
	})
	got := m.teamBudgetLine()
	for _, want := range []string{"cap 200% of one core", "45.5s used", "107.6s throttled"} {
		if !strings.Contains(got, want) {
			t.Errorf("budget line %q\n  is missing %q", got, want)
		}
	}
}

// Each lane reports its own consumption against its own caps, and says nothing
// until it has two readings — a rate needs an interval.
func TestALanesUsageLineIsItsOwn(t *testing.T) {
	m := teamModel()
	now := time.Now()
	sample := func(cpu float64, at time.Time) teamUsageMsg {
		return teamUsageMsg{at: at, per: []agentUsage{{"master", usageMsg{
			usage: sandbox.Usage{CPUSeconds: cpu, RSSKiB: 50 << 10},
			state: sandbox.State{ID: "aaaa", CPUQuota: 150, MemMiB: 512}, at: at}}}}
	}
	if got := m.lanes["master"].laneUsage(m.agentReceipt("master")); !strings.Contains(got, "waiting") {
		t.Errorf("a lane with no sample reported one: %q", got)
	}
	m.Update(sample(1.0, now))
	if got := m.lanes["master"].laneUsage(m.agentReceipt("master")); !strings.Contains(got, "cpu —") {
		t.Errorf("a single sample reported a rate: %q", got)
	}
	m.Update(sample(1.5, now.Add(time.Second)))
	got := m.lanes["master"].laneUsage(m.agentReceipt("master"))
	for _, want := range []string{"cpu 50%/150%", "mem 50 MiB/512M"} {
		if !strings.Contains(got, want) {
			t.Errorf("lane usage %q\n  is missing %q", got, want)
		}
	}
	// The other agent has no reading of its own and must not borrow one.
	if got := m.lanes["worker-1"].laneUsage(m.agentReceipt("worker-1")); !strings.Contains(got, "waiting") {
		t.Errorf("a lane borrowed another agent's numbers: %q", got)
	}
}

// A team that stopped still has its receipts, one per agent, from the chain.
func TestALaneFallsBackToItsOwnReceipt(t *testing.T) {
	m := teamModel()
	m.absorb(recorder.Event{Type: recorder.TypeResourceSummary, Agent: "master",
		TS: "2026-08-23T10:01:00.000Z", CPUSeconds: 3.15, PeakRSSKiB: 49 << 10})
	if got := m.lanes["master"].laneUsage(m.agentReceipt("master")); !strings.Contains(got, "final 3.1s cpu") {
		t.Errorf("the lane did not fall back to its receipt: %q", got)
	}
	// A per-agent receipt is not the session's.
	if m.d.Receipt != nil {
		t.Error("an agent's receipt was taken as the session's")
	}
}

// The single-sandbox view must be untouched by all of this.
func TestASingleSandboxStillGetsTheSingleView(t *testing.T) {
	m := &watchModel{session: "abcd1234", started: time.Now()}
	m.absorb(recorder.Event{Type: recorder.TypeCommandStart, TS: "2026-08-23T10:00:00.000Z",
		Cmd: []string{"ls"}, Call: "c1", Via: "exec"})
	if len(m.order) != 0 {
		t.Fatalf("a single sandbox grew lanes: %v", m.order)
	}
	// render() rather than View(): the view is now a struct carrying the
	// terminal's mode alongside the content, and what this test is about is
	// the content.
	out := m.render()
	if strings.Contains(out, "message flow") {
		t.Error("the single-sandbox view rendered the team ticker")
	}
	if !strings.Contains(out, "sandbox abcd1234") {
		t.Error("the single-sandbox header changed")
	}
}

// A lane is created the first time its agent is *seen*, and sampling sees every
// agent at once. Ranging a map to do that put the columns in a different order
// on every run — which the first live render showed, so it is pinned here.
func TestSamplingCreatesLanesInBootOrder(t *testing.T) {
	at := time.Now()
	m := &watchModel{session: "team1234", started: at}
	m.Update(teamUsageMsg{at: at, per: []agentUsage{
		{"master", usageMsg{state: sandbox.State{ID: "a"}, at: at}},
		{"worker-1", usageMsg{state: sandbox.State{ID: "b"}, at: at}},
		{"worker-2", usageMsg{state: sandbox.State{ID: "c"}, at: at}},
	}})
	if got := strings.Join(m.order, " "); got != "master worker-1 worker-2" {
		t.Errorf("lanes = %q, want the roster's order", got)
	}
}

// A lane's lines carry no timestamp: twelve characters of clock in front of
// every line leaves nothing for the line. The clock is in the ticker, which is
// full width.
func TestLaneLinesSpendTheirWidthOnContent(t *testing.T) {
	m := teamModel()
	for _, line := range m.lanes["master"].lines {
		if strings.Contains(line, "10:00:0") {
			t.Errorf("a lane line spends its width on a timestamp: %q", line)
		}
	}
	// The session-wide list keeps its timestamps: it is full width.
	for _, line := range m.lines {
		if !strings.Contains(line, "10:00:0") {
			t.Errorf("a session-wide line lost its timestamp: %q", line)
		}
	}
	// And the ticker carries the clock for the messages.
	if !strings.Contains(strings.Join(m.flow, "\n"), "10:00:0") {
		t.Error("the ticker has no timestamps")
	}
}

// P7-7: watch opens on the activity pane exactly as it always rendered —
// switching panes must be something a key does, not something that changes
// what a session with no key pressed shows.
func TestWatchOpensOnTheActivityPaneByDefault(t *testing.T) {
	m := teamModel()
	m.width, m.height = 100, 30
	if m.pane != paneActivity {
		t.Fatalf("pane = %v, want paneActivity", m.pane)
	}
	out := m.render()
	if strings.Contains(out, "map — declared topology") || strings.Contains(out, "AGENT") {
		t.Errorf("the default render already shows a P7-7 pane:\n%s", out)
	}
}

// The three panes are reachable by number and by mnemonic, and quitting
// still works from any of them.
func TestWatchKeysSwitchPanes(t *testing.T) {
	m := teamModel()
	m.width, m.height = 100, 30
	for key, want := range map[string]pane{"2": paneMap, "m": paneMap, "3": paneSheet, "s": paneSheet, "1": paneActivity, "v": paneActivity} {
		m.pane = paneActivity
		m.Update(pressKey(key))
		if m.pane != want {
			t.Errorf("key %q switched to pane %v, want %v", key, m.pane, want)
		}
	}
	m.pane = paneMap
	_, cmd := m.Update(pressKey("q"))
	if cmd == nil {
		t.Error("q did not quit from a non-default pane")
	}
}

// The map pane draws a team's recorded topology once team.topology has
// landed, and says so plainly before it has.
func TestMapPaneDrawsTheRecordedTopology(t *testing.T) {
	m := &watchModel{session: "team1234", started: time.Now(), width: 100, height: 30}
	if out := m.mapPane(m.width, m.height); !strings.Contains(out, "waiting for") {
		t.Errorf("no topology yet, and the pane did not say so: %q", out)
	}

	topo := recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: []recorder.EvAgent{{Name: "master", Sandbox: "aaa"}, {Name: "worker-1", Sandbox: "bbb"}},
		Edges:  []string{"master -> worker-1", "worker-1 -> master"},
	})
	m.absorb(topo)
	out := m.mapPane(m.width, m.height)
	for _, want := range []string{"master", "worker-1", "2 agents", "2 edges"} {
		if !strings.Contains(out, want) {
			t.Errorf("map pane is missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, paneHint) {
		t.Error("the map pane does not carry the pane-switching hint")
	}
}

// Outside a team, the map pane still draws something — the single machine's
// own declared reach — once its session.policy has landed.
func TestMapPaneDrawsASingleMachineOutsideATeam(t *testing.T) {
	m := &watchModel{session: "abcd1234", started: time.Now(), width: 100, height: 30}
	policy := recorder.NewSessionPolicy("", recorder.PolicyFields{Allow: []string{"example.com"}})
	m.absorb(policy)
	out := m.mapPane(m.width, m.height)
	if !strings.Contains(out, "example.com") {
		t.Errorf("a single sandbox's own allowlist did not reach the map pane: %q", out)
	}
}

// The agent sheet shows each agent's declared caps beside its live counters,
// with the header row naming every column.
func TestSheetPaneShowsCapsBesideCounters(t *testing.T) {
	m := teamModel()
	m.width, m.height = 100, 30
	policy := recorder.NewSessionPolicy("master", recorder.PolicyFields{
		VcpuCount: 2, MemMiB: 512, CPUQuota: 50, Allow: []string{"a.com", "b.com"},
	})
	m.absorb(policy)
	out := m.sheetPane(m.width, m.height)
	for _, want := range []string{"AGENT", "CAPS", "master", "2c/512M/50%", "worker-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("agent sheet is missing %q:\n%s", want, out)
		}
	}
}

// pressKey builds the tea.KeyPressMsg m.Update expects, for a plain
// single-rune key with no modifiers.
func pressKey(s string) tea.KeyPressMsg {
	return tea.KeyPressMsg{Text: s, Code: rune(s[0])}
}

// A live watch's own Digest never retains Timeline (KeepTimeline is false
// for a zero-value Digest), so the map pane's "refused since boot" section
// cannot read it back the way `kelyfos team ps --graph` does — it has to be
// tracked live, as each refusal is absorbed, which is exactly what
// teamModel() (the fixture used above) already does via its team.refused and
// team.store events.
func TestMapPaneShowsLiveRefusalsWithTheirFixLine(t *testing.T) {
	m := teamModel()
	m.width, m.height = 100, 30
	m.absorb(recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: []recorder.EvAgent{{Name: "master", Sandbox: "a"}, {Name: "worker-1", Sandbox: "b"}},
		Edges:  []string{"master -> worker-1"},
	}))
	out := m.mapPane(m.width, m.height)
	if !strings.Contains(out, "refused since boot") {
		t.Fatalf("no refusals section even though teamEvents() carries a no_edge and a denied store "+
			"access:\n%s", out)
	}
	for _, want := range []string{"add [[team.edge]]", "add \"worker-1\" to read"} {
		if !strings.Contains(out, want) {
			t.Errorf("map pane is missing the fix line %q:\n%s", want, out)
		}
	}
}

// Neither pane may emit more lines than its own height, note included — the
// off-by-one a review caught: the old logic picked a full budget's worth of
// content and then appended a truncation note on top of it.
//
// The floor starts at 4, not 1: both panes' chrome is a fixed
// header + rule + hint, joined with "\n" around whatever body content the
// budget allows — even a zero-width body still costs a line for the
// separator between "rule" and "hint" ("header\nrule\n\nhint"). Going below
// 4 would mean conditionally dropping the rule or the hint for a terminal
// too small to show either meaningfully, which is real UI work this task
// was never asked to do — the review's own realistic case was 120x24, and
// nobody runs `kelyfos watch` in a 2-line terminal. 4 is the true minimum:
// verified by removing fitToBudget's own floor of 1 and confirming the
// total is still 4, not fewer, at height 1-3.
func TestMapAndSheetPanesNeverExceedTheirHeightBudget(t *testing.T) {
	m := teamModel()
	m.width = 100
	m.absorb(recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: []recorder.EvAgent{{Name: "master", Sandbox: "a"}, {Name: "worker-1", Sandbox: "b"}},
		Edges:  []string{"master -> worker-1", "worker-1 -> master"},
	}))
	for h := 4; h <= 30; h++ {
		if got := strings.Count(m.mapPane(m.width, h), "\n") + 1; got > h {
			t.Errorf("mapPane(height=%d) emitted %d lines", h, got)
		}
		if got := strings.Count(m.sheetPane(m.width, h), "\n") + 1; got > h {
			t.Errorf("sheetPane(height=%d) emitted %d lines", h, got)
		}
	}
}

// A real refusal must survive truncation at a real, small terminal size —
// the failure a review captured live under tmux at 120x24 against a real
// 5-agent team: the refusals section, the whole edge table and the
// pane-switching hint were all off-screen, because the old logic truncated
// from the top of one monolithic string and the graph body alone was
// already longer than the window.
func TestMapPaneRefusalsSurviveTruncationAtARealisticHeight(t *testing.T) {
	m := &watchModel{session: "team1234", started: time.Now(), width: 120}
	agents := make([]recorder.EvAgent, 0, 8)
	var edges []string
	for i := 1; i <= 8; i++ {
		name := fmt.Sprintf("worker-%d", i)
		agents = append(agents, recorder.EvAgent{Name: name, Sandbox: fmt.Sprintf("sb%d", i)})
		edges = append(edges, "master -> "+name, name+" -> master")
	}
	agents = append(agents, recorder.EvAgent{Name: "master", Sandbox: "sbm"})
	m.absorb(recorder.NewTeamTopology(recorder.TopologyFields{Agents: agents, Edges: edges}))
	m.absorb(recorder.Event{Type: recorder.TypeTeamRefused, Agent: "worker-1", Peer: "worker-2",
		Kind: "send", Reason: "no_edge"})

	out := m.mapPane(m.width, 24)
	if got := strings.Count(out, "\n") + 1; got > 24 {
		t.Fatalf("mapPane emitted %d lines at height 24", got)
	}
	for _, want := range []string{"refused since boot", "add [[team.edge]]", paneHint} {
		if !strings.Contains(out, want) {
			t.Errorf("at a realistic 120x24, the map pane is missing %q:\n%s", want, out)
		}
	}
}

// The live map pane has the same two honest gaps as `kelyfos team ps
// --graph` (host/teamgraph.go), since it reads the same recorded
// team.topology: a store enabled with zero rules still needs its synthetic
// resource and a caveat, and a runtime-spawned agent gets an explicit note
// rather than being silently folded into the declared picture.
func TestMapPaneCaveatsMatchTeamPSGraphsHonestGaps(t *testing.T) {
	m := teamModel() // absorbs master, worker-1 via teamEvents()
	m.width, m.height = 100, 40
	m.absorb(recorder.NewTeamTopology(recorder.TopologyFields{
		Agents: []recorder.EvAgent{{Name: "master"}, {Name: "worker-1"}},
	}))
	// A worker this fixture's own events already named, but that the
	// topology above does not list, stands in for a runtime spawn.
	m.absorb(recorder.Event{Type: recorder.TypeCommandStart, Agent: "worker-1-spawn-1",
		Cmd: []string{"true"}, Call: "cX"})

	out := m.mapPane(m.width, m.height)
	if !strings.Contains(out, "team.store") && !strings.Contains(out, "P7-3 recorder gap") {
		t.Errorf("no store-enabled-ambiguity caveat for a topology with zero store rules:\n%s", out)
	}
	if !strings.Contains(out, "spawned at runtime") || !strings.Contains(out, "worker-1-spawn-1") {
		t.Errorf("no note naming the agent spawned at runtime, not in the declared topology:\n%s", out)
	}
}

// kelyfos watch --json (P7-10): a one-shot snapshot of the digest, printed
// to stdout and nothing else — no alt screen, no bubbletea program, no
// interactive state. This writes a real JSONL file (no hash chain needed:
// recorder.Read only parses, it does not verify) and reads watchJSON's
// stdout back through a pipe, the same technique host/log_test.go's
// renderEvent already uses for printEvent.
func TestWatchJSONPrintsASnapshotAndExitsWithoutOpeningTheTUI(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, e := range teamEvents() {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	watchErr := watchJSON(path)
	os.Stdout = saved
	w.Close()
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if watchErr != nil {
		t.Fatalf("watchJSON returned an error: %v", watchErr)
	}

	var s digest.Snapshot
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("watchJSON's stdout is not valid Snapshot JSON: %v\n%s", err, out)
	}
	if !s.Team {
		t.Errorf("snapshot of a team session has Team=false: %+v", s)
	}
	if s.Events == 0 {
		t.Error("snapshot has Events=0 for a non-empty fixture")
	}
	if len(s.Agents) != 2 {
		t.Errorf("snapshot has %d agents, want 2 (master, worker-1)", len(s.Agents))
	}
}
