package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// watchCmd is a live view of a sandbox, or of a whole team.
//
// It reads the flight recorder and nothing else — it never opens a channel to
// the guest, never sends a command, and quitting it does not touch the sandbox.
// That is decision D7's line: viewers read the JSONL, managers change things,
// and this is a viewer. The host counters it samples alongside are readings
// rather than records, which is the distinction F-D14 draws.
//
// A team needs no second command and no flag: a team is one session (E2-7), so
// the same file feeds both views and the events' own `agent` field is what
// splits it into lanes (E2-8, superseding P4-6 for the team case).
func watchCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos watch", flag.ExitOnError)
	id := fs.String("session", "", "session id (default: the most recent)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos watch [flags]

A live view of a sandbox, built entirely from its flight recorder. It does not
talk to the guest and quitting it leaves the sandbox running.

A team session shows one lane per agent — its commands, files, egress and what
it is consuming against its own caps — with the messages between agents in a
ticker underneath and the team's collective budget above. There is no flag for
it: a session whose events name agents is a team.

  q, esc, ctrl-c   quit

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	sessionID, err := resolveSession(*id)
	if err != nil {
		return err
	}
	path := recorder.Path(sandbox.Root(), sessionID)

	m := &watchModel{session: sessionID, path: path, started: time.Now()}
	p := tea.NewProgram(m, tea.WithAltScreen())
	m.program = p
	go m.tail()
	_, err = p.Run()
	return err
}

type eventMsg recorder.Event
type tickMsg time.Time

// usageMsg is one reading of what the sandbox is consuming. It is the one thing
// this view does not get from the flight recorder, and F-D14 records why: a
// live gauge of a running machine is a reading, not a record, and writing a
// sample per second into a tamper-evident log to display it would be inventing
// a metrics store nobody asked for. The durable number is the single
// resource.summary written at teardown, which this view also renders.
type usageMsg struct {
	usage sandbox.Usage
	state sandbox.State
	at    time.Time
}

// lane is one agent's column in a team view: its own recent activity, its own
// counters, and its own reading of what it is consuming.
//
// A team is one session (E2-7), so all of this comes out of one file — the lane
// is a split of the chain by the `agent` field, not a second source of truth.
type lane struct {
	name    string
	sandbox string
	lines   []string

	commands, failed, files, egressOK, egressBlocked, secrets int

	live, prev *usageMsg
	cpuPercent float64
	receipt    *recorder.Event
}

type watchModel struct {
	session string
	path    string
	started time.Time
	program *tea.Program

	width, height int
	lines         []string

	// The team view. order is first-appearance order, which is boot order, so
	// the columns read like the file the user wrote. Empty until an event
	// carrying an agent arrives, at which point the view becomes a team view —
	// there is no flag to set and nothing to ask the user.
	order []string
	lanes map[string]*lane
	// flow is the message ticker: who told what to whom, most recent last. It
	// is full width under the lanes rather than inside one, because a message
	// belongs to two agents and putting it in either lane would be a choice
	// about which.
	flow []string
	// The team's collective cap, when it has one (E2-6).
	teamCGroup string
	teamQuota  int
	teamCPU    float64
	teamThrott float64

	// counters for the status line
	commands, failed, files, egressOK, egressBlocked, secrets int
	// team-wide counters, which belong to no single lane
	messages, refused        int
	image, kernel, endReason string
	bootMS                   int64

	// the resources lane: a live sample while the sandbox runs, and the
	// recorded receipt once it has stopped
	live, prev *usageMsg
	cpuPercent float64
	receipt    *recorder.Event
}

func (m *watchModel) Init() tea.Cmd { return tea.Batch(tick(), sampleUsage(m.session)) }

// teamUsageMsg is one reading of every agent in a running team, plus the
// team's own collective figures. Like usageMsg it is a reading and not a
// record: the durable numbers are the per-agent receipts the recorder keeps
// (F-D14).
type teamUsageMsg struct {
	// Ordered, not a map. Sampling is also the moment a lane is first created
	// for an agent that has not done anything yet, and ranging a map to do that
	// would put the columns in a different order on every run — which was not
	// a theory, it is what the first live render showed.
	per        []agentUsage
	cgroup     string
	quota      int
	cpuSeconds float64
	throttled  float64
	at         time.Time
}

type agentUsage struct {
	name  string
	usage usageMsg
}

// sampleTeam reads the host's counters for every agent in the running team,
// and the parent slice's own accounting. A team that has stopped has no state
// file, and every lane falls back to the receipt in the chain.
func sampleTeam() tea.Cmd {
	return func() tea.Msg {
		st, err := readTeamState()
		if err != nil {
			return nil
		}
		// st.Agents is the roster's order, which is boot order.
		msg := teamUsageMsg{cgroup: st.CGroup, quota: st.CPUQuota, at: time.Now()}
		for _, a := range st.Agents {
			sb, err := sandbox.Load(a.Sandbox)
			if err != nil {
				continue
			}
			u, err := sb.Sample()
			if err != nil {
				continue
			}
			msg.per = append(msg.per, agentUsage{a.Name, usageMsg{usage: u, state: *sb, at: msg.at}})
		}
		if st.CGroup != "" {
			if stat, err := sandbox.CPUStatAt(st.CGroup); err == nil {
				msg.cpuSeconds = float64(stat["usage_usec"]) / 1e6
				msg.throttled = float64(stat["throttled_usec"]) / 1e6
			}
		}
		return msg
	}
}

// sampleUsage reads the host's counters for this sandbox, if it is still
// running. A sandbox that has stopped simply has no state file, and the lane
// falls back to the recorded receipt.
func sampleUsage(id string) tea.Cmd {
	return func() tea.Msg {
		st, err := sandbox.Load(id)
		if err != nil {
			return nil
		}
		u, err := st.Sample()
		if err != nil {
			return nil
		}
		return usageMsg{usage: u, state: *st, at: time.Now()}
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// tail follows the recorder from the beginning, so opening the watch part-way
// through a session still shows what happened before it started.
func (m *watchModel) tail() {
	var f *os.File
	for i := 0; ; i++ {
		var err error
		if f, err = os.Open(m.path); err == nil {
			break
		}
		if i > 300 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var e recorder.Event
			if json.Unmarshal(line, &e) == nil {
				m.program.Send(eventMsg(e))
			}
		}
		if err == io.EOF {
			time.Sleep(120 * time.Millisecond)
			continue
		}
		if err != nil {
			return
		}
	}
}

func (m *watchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
	case tickMsg:
		// A team samples every agent; a single sandbox samples itself. Which
		// one this is was decided by the chain, not by a flag.
		if len(m.order) > 0 {
			return m, tea.Batch(tick(), sampleTeam())
		}
		return m, tea.Batch(tick(), sampleUsage(m.session))
	case teamUsageMsg:
		m.teamCGroup, m.teamQuota = msg.cgroup, msg.quota
		m.teamCPU, m.teamThrott = msg.cpuSeconds, msg.throttled
		for _, au := range msg.per {
			l := m.lane(au.name)
			l.sandbox = au.usage.state.ID
			if l.live != nil {
				if dt := au.usage.at.Sub(l.live.at).Seconds(); dt > 0 {
					l.cpuPercent = 100 * (au.usage.usage.CPUSeconds - l.live.usage.CPUSeconds) / dt
				}
			}
			sample := au.usage
			l.prev, l.live = l.live, &sample
		}
	case usageMsg:
		// CPU is a rate, so it needs two readings. The first tick shows the
		// machine's shape and no percentage, which is honest: nothing has been
		// measured over an interval yet.
		if m.live != nil {
			if dt := msg.at.Sub(m.live.at).Seconds(); dt > 0 {
				m.cpuPercent = 100 * (msg.usage.CPUSeconds - m.live.usage.CPUSeconds) / dt
			}
		}
		m.prev, m.live = m.live, &msg
	case eventMsg:
		m.absorb(recorder.Event(msg))
	}
	return m, nil
}

// lane returns an agent's lane, creating it the first time that agent is seen.
// Creation order is the lane order, and the first lane created is what turns
// this into a team view.
func (m *watchModel) lane(name string) *lane {
	if m.lanes == nil {
		m.lanes = map[string]*lane{}
	}
	l, ok := m.lanes[name]
	if !ok {
		l = &lane{name: name}
		m.lanes[name] = l
		m.order = append(m.order, name)
	}
	return l
}

// bound keeps a line buffer to what can ever be shown. An unbounded slice in a
// long session is a slow leak nobody would notice until it mattered.
func bound(lines []string, max int) []string {
	if len(lines) > max {
		return lines[len(lines)-max:]
	}
	return lines
}

func (m *watchModel) absorb(e recorder.Event) {
	// A team writes one receipt per agent; only a single sandbox's receipt is
	// the session's (E2-7).
	if e.Type == recorder.TypeResourceSummary {
		ev := e
		if e.Agent != "" {
			m.lane(e.Agent).receipt = &ev
		} else {
			m.receipt = &ev
		}
	}
	ts := e.TS
	if len(ts) > 23 {
		ts = ts[11:23]
	}
	// An event that names an agent goes into that agent's lane; everything else
	// goes to the shared list, which is the whole view for a single sandbox and
	// the team-wide line for a team.
	var target *[]string = &m.lines
	if e.Agent != "" {
		target = &m.lane(e.Agent).lines
	}
	// A lane is narrow, and twelve characters of timestamp in front of every
	// line leaves nothing for the line. The clock lives in the ticker, which is
	// full width, and at full precision in `kelyfos log`; a lane's job is to
	// show what its agent is doing.
	add := func(style lipgloss.Style, label, text string) {
		if e.Agent != "" {
			*target = append(*target, style.Render(fmt.Sprintf("%-7s", label))+" "+text)
		} else {
			*target = append(*target, fmt.Sprintf("%s %s %s",
				dim.Render(ts), style.Render(fmt.Sprintf("%-9s", label)), text))
		}
		*target = bound(*target, 500)
	}
	// The ticker carries the messages between agents. They are the one kind of
	// event that belongs to two lanes, so they belong in neither.
	tick := func(text string) {
		m.flow = bound(append(m.flow, dim.Render(ts)+" "+text), 200)
	}
	// counters: an agent's own when it has one, the session's otherwise.
	commands, failed, files := &m.commands, &m.failed, &m.files
	egressOK, egressBlocked, secrets := &m.egressOK, &m.egressBlocked, &m.secrets
	if e.Agent != "" {
		l := m.lane(e.Agent)
		commands, failed, files = &l.commands, &l.failed, &l.files
		egressOK, egressBlocked, secrets = &l.egressOK, &l.egressBlocked, &l.secrets
	}

	switch e.Type {
	case recorder.TypeSessionStart:
		m.image = e.Image + " · " + e.Arch
		add(styleMuted, "session", "start "+m.image)
	case recorder.TypeSessionReady:
		m.bootMS, m.kernel = e.BootMS, e.Kernel
		add(styleOK, "ready", fmt.Sprintf("%d ms · kernel %s", e.BootMS, e.Kernel))
	case recorder.TypeSessionEnd:
		m.endReason = e.Reason
		add(styleMuted, "session", "end "+e.Reason)
	case recorder.TypeCommandStart:
		*commands++
		add(styleCmd, "$", strings.Join(e.Cmd, " "))
	case recorder.TypeCommandOutput:
		data, _ := base64.StdEncoding.DecodeString(e.Data)
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			style, mark := styleDim, "|"
			if e.Stream == "stderr" {
				style, mark = styleWarn, "!"
			}
			add(style, mark, l)
		}
	case recorder.TypeCommandExit:
		code := -1
		if e.Code != nil {
			code = *e.Code
		}
		style := styleOK
		if code != 0 {
			style = styleWarn
			*failed++
		}
		add(style, "exit", fmt.Sprintf("%d · %d ms", code, e.DurationMS))
	case recorder.TypeFileWrite:
		*files++
		add(styleAmber, "write", fmt.Sprintf("%s · %d bytes", e.Path, e.Bytes))
	case recorder.TypeEgressAttempt:
		if e.Allowed != nil && *e.Allowed {
			*egressOK++
			add(styleOK, "egress", fmt.Sprintf("%s:%d · %s", e.Host, e.Port, e.Mode))
		} else {
			*egressBlocked++
			add(styleWarn, "BLOCKED", fmt.Sprintf("%s:%d · %s", e.Host, e.Port, e.Reason))
		}
	case recorder.TypeSecretUse:
		*secrets++
		add(styleAmber, "secret", e.Name+" → "+e.Host)
	case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
		// Named so the two ends are both visible: an ask points forward, a
		// reply back, and a refusal says so before it says anything else.
		arrow := "→"
		if e.Kind == "reply" {
			arrow = "←"
		}
		body := fmt.Sprintf("%s %s %s  %s · %d bytes", e.Agent, arrow, e.Peer, e.Kind, e.Bytes)
		if e.Type == recorder.TypeTeamRefused {
			m.refused++
			tick(styleWarn.Render("REFUSED ") + body + dim.Render("  ("+e.Reason+")"))
			break
		}
		m.messages++
		tick(styleMuted.Render("msg     ") + body)
	case recorder.TypeTeamStore:
		// A store access is something one agent did, so it goes in that
		// agent's lane — and also in the ticker when it was refused, because a
		// refusal is the thing a watcher is watching for.
		style, label := styleAmber, "store"
		if e.Outcome != "delivered" {
			style, label = styleWarn, "DENIED"
			m.refused++
			tick(styleWarn.Render("DENIED  ") +
				fmt.Sprintf("%s %s %s", e.Agent, e.Kind, e.Peer) + dim.Render("  ("+e.Reason+")"))
		}
		add(style, label, fmt.Sprintf("%s %s", e.Kind, e.Peer))
	case recorder.TypeTeamSpawn:
		if e.Outcome != "delivered" {
			m.refused++
			tick(styleWarn.Render("REFUSED ") + e.Agent + " may not spawn" + dim.Render("  ("+e.Reason+")"))
			break
		}
		tick(styleOK.Render("spawn   ") + fmt.Sprintf("%s %s by %s", e.Kind, e.Peer, e.Agent))
	case recorder.TypeResourceOOM:
		add(styleWarn, "OOM", fmt.Sprintf("%s (pid %d) holding %s", e.Comm, e.PID, report.HumanKiB(e.RSSKiB)))
	}
}

var (
	dim        = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleMuted = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleDim   = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("78"))
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleAmber = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleCmd   = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Bold(true)
	titleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	barStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

func (m *watchModel) View() string {
	width := m.width
	if width < 40 {
		width = 80
	}
	height := m.height
	if height < 10 {
		height = 24
	}

	// The chain decides which view this is: a session that carries agents is a
	// team, and there is nothing to ask the user.
	if len(m.order) > 0 {
		return m.teamView(width, height)
	}

	state := "running"
	if m.endReason != "" {
		state = "stopped (" + m.endReason + ")"
	}
	header := fmt.Sprintf("%s  sandbox %s  %s  %s",
		titleStyle.Render("KelyfOS"), m.session, m.image, state)

	status := barStyle.Render(fmt.Sprintf(
		"uptime %s · boot %d ms · %d commands (%d failed) · %d files · egress %d ok / %d blocked · %d secret uses",
		time.Since(m.started).Truncate(time.Second), m.bootMS,
		m.commands, m.failed, m.files, m.egressOK, m.egressBlocked, m.secrets))

	resources := m.resourceLane()

	// Chrome: header, status, resources, rule, and the quit hint.
	lane := height - 5
	if lane < 1 {
		lane = 1
	}
	shown := m.lines
	if len(shown) > lane {
		shown = shown[len(shown)-lane:]
	}
	body := strings.Join(shown, "\n")
	if body == "" {
		body = dim.Render("  waiting for events…")
	}

	return header + "\n" + status + "\n" + resources + "\n" +
		strings.Repeat("─", min(width, 120)) + "\n" +
		body + "\n" + dim.Render("q to quit — the sandbox keeps running")
}

// laneMinWidth is the narrowest a lane can be and still say anything. Below it
// the view stops pretending: N columns of eight characters is not a team view,
// it is a puzzle.
const laneMinWidth = 22

// teamView renders one lane per agent, a message ticker under them, and the
// team's collective figures above.
//
// Everything here is a reader of the flight recorder plus host counters —
// nothing is sent to any guest, and quitting changes nothing (D7, F-D14).
func (m *watchModel) teamView(width, height int) string {
	n := len(m.order)
	// Two columns of separator between lanes.
	laneW := (width - 2*(n-1)) / n
	narrow := laneW < laneMinWidth

	state := "running"
	if m.endReason != "" {
		state = "stopped (" + m.endReason + ")"
	}
	header := fmt.Sprintf("%s  team session %s  %d agents  %s",
		titleStyle.Render("KelyfOS"), m.session, n, state)
	status := barStyle.Render(fmt.Sprintf(
		"uptime %s · %d messages · %d refused · %d commands (%d failed) · egress %d ok / %d blocked",
		time.Since(m.started).Truncate(time.Second),
		m.messages, m.refused, m.teamCommands(), m.teamFailed(),
		m.teamEgressOK(), m.teamEgressBlocked()))
	budget := m.teamBudgetLine()

	// Chrome: header, status, budget, rule, lane headers (2), rule, ticker
	// heading, ticker lines, hint.
	flowH := 4
	chrome := 4 + 2 + 1 + 1 + flowH + 1
	laneH := height - chrome
	if laneH < 3 {
		laneH = 3
	}

	var body string
	if narrow {
		// One column, with each line saying which agent it came from — the same
		// answer `kelyfos log` gives, and an honest one: it is the information
		// without the layout, rather than the layout without the information.
		var merged []string
		for _, name := range m.order {
			for _, ln := range m.lanes[name].lines {
				merged = append(merged, dim.Render("["+name+"]")+" "+ln)
			}
		}
		body = dim.Render(fmt.Sprintf(
			"  terminal is %d columns; %d lanes need %d — showing one column instead",
			width, n, n*laneMinWidth+2*(n-1))) + "\n" +
			strings.Join(bound(merged, laneH-1), "\n")
	} else {
		cols := make([][]string, n)
		for i, name := range m.order {
			cols[i] = m.laneBlock(m.lanes[name], laneW, laneH)
		}
		rows := make([]string, laneH+2)
		for r := range rows {
			parts := make([]string, n)
			for i := range cols {
				parts[i] = cols[i][r]
			}
			rows[r] = strings.Join(parts, dim.Render("│ "))
		}
		body = strings.Join(rows, "\n")
	}

	flow := m.flow
	if len(flow) > flowH {
		flow = flow[len(flow)-flowH:]
	}
	ticker := strings.Join(flow, "\n")
	if ticker == "" {
		ticker = dim.Render("  no messages between agents yet")
	}

	rule := strings.Repeat("─", min(width, 200))
	return header + "\n" + status + "\n" + budget + "\n" + rule + "\n" +
		body + "\n" + rule + "\n" +
		barStyle.Render("message flow") + "\n" + ticker + "\n" +
		dim.Render("q to quit — the team keeps running")
}

// laneBlock renders one agent's column as exactly laneH+2 lines of exactly
// laneW columns: a name, a resource line, then its activity.
//
// The width is fixed here rather than left to the terminal, because columns
// that are only usually the same width are not columns.
func (m *watchModel) laneBlock(l *lane, laneW, laneH int) []string {
	out := make([]string, 0, laneH+2)
	out = append(out, titleStyle.Render(fit(l.name, laneW)))
	out = append(out, barStyle.Render(fit(l.laneUsage(), laneW)))
	lines := bound(l.lines, laneH)
	for _, ln := range lines {
		out = append(out, fitStyled(ln, laneW))
	}
	for len(out) < laneH+2 {
		out = append(out, strings.Repeat(" ", laneW))
	}
	return out
}

// laneUsage is one agent's consumption against its own caps, in one line.
func (l *lane) laneUsage() string {
	if l.live != nil {
		st, u := l.live.state, l.live.usage
		cpu := "cpu —"
		if l.prev != nil {
			cpu = fmt.Sprintf("cpu %.0f%%", l.cpuPercent)
		}
		switch {
		case st.CPUQuota > 0:
			cpu += fmt.Sprintf("/%d%%", st.CPUQuota)
		case st.VcpuCount > 0:
			cpu += fmt.Sprintf("/%d core", st.VcpuCount)
		}
		return fmt.Sprintf("%s  mem %s/%dM", cpu, report.HumanKiB(u.RSSKiB), st.MemMiB)
	}
	if l.receipt != nil {
		return fmt.Sprintf("final %.1fs cpu, peak %s",
			l.receipt.CPUSeconds, report.HumanKiB(l.receipt.PeakRSSKiB))
	}
	return "waiting…"
}

// teamBudgetLine is the collective cap and what the team has spent against it,
// read from the parent cgroup the cap is written on so the two cannot be about
// different things (E2-6).
func (m *watchModel) teamBudgetLine() string {
	if m.teamCGroup == "" {
		return dim.Render("  team budget: none declared")
	}
	cap := "no collective cap"
	if m.teamQuota > 0 {
		cap = fmt.Sprintf("cap %d%% of one core", m.teamQuota)
	}
	line := fmt.Sprintf("team budget · %s · %.1fs used", cap, m.teamCPU)
	if m.teamThrott > 0 {
		line += fmt.Sprintf(" · %.1fs throttled", m.teamThrott)
	}
	return barStyle.Render(line)
}

func (m *watchModel) teamCommands() int { return m.sum(func(l *lane) int { return l.commands }) }
func (m *watchModel) teamFailed() int   { return m.sum(func(l *lane) int { return l.failed }) }
func (m *watchModel) teamEgressOK() int { return m.sum(func(l *lane) int { return l.egressOK }) }
func (m *watchModel) teamEgressBlocked() int {
	return m.sum(func(l *lane) int { return l.egressBlocked })
}

func (m *watchModel) sum(f func(*lane) int) int {
	n := 0
	for _, l := range m.lanes {
		n += f(l)
	}
	return n
}

// fit pads or truncates a plain string to exactly w columns. Every line this
// renders is ASCII plus a handful of single-width symbols, so counting runes is
// counting columns; a wide-character guest path name would be the exception,
// and the cost of getting it wrong is a ragged column rather than a wrong fact.
func fit(s string, w int) string {
	r := []rune(s)
	if len(r) > w {
		if w <= 1 {
			return strings.Repeat(" ", max(w, 0))
		}
		return string(r[:w-1]) + "…"
	}
	return s + strings.Repeat(" ", w-len(r))
}

// fitStyled does the same for a line that already carries colour, by measuring
// what the terminal will actually show rather than the bytes.
func fitStyled(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s + strings.Repeat(" ", w-lipgloss.Width(s))
	}
	// Trim from the end a rune at a time: the styles are prefixes, so cutting
	// the tail keeps every escape sequence balanced.
	r := []rune(s)
	for len(r) > 0 && lipgloss.Width(string(r)) > w-1 {
		r = r[:len(r)-1]
	}
	return string(r) + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// resourceLane shows consumption against the caps it is consumed under. Every
// figure is measured on the host — the guest is never asked, which is what
// makes the line worth reading (F-D2).
func (m *watchModel) resourceLane() string {
	if m.live != nil {
		st, u := m.live.state, m.live.usage
		cpu := "cpu   —"
		if m.prev != nil {
			cpu = fmt.Sprintf("cpu %5.1f%%", m.cpuPercent)
		}
		switch {
		case st.CPUQuota > 0:
			cpu += fmt.Sprintf(" of %d%% quota", st.CPUQuota)
		case st.VcpuCount > 0:
			cpu += fmt.Sprintf(" of %d core(s), no quota", st.VcpuCount*100)
		}
		// The VMM's resident set, not the guest's: it holds the guest's memory
		// and whatever the host has cached for the guest's disks, so it can sit
		// above the machine's RAM without the machine having exceeded it.
		mem := fmt.Sprintf("mem %s (VMM)", report.HumanKiB(u.RSSKiB))
		if st.MemMiB > 0 {
			mem += fmt.Sprintf(", machine %d MiB", st.MemMiB)
		}
		net := fmt.Sprintf("net %s in / %s out", humanBytes(u.NetInBytes), humanBytes(u.NetOutBytes))
		if st.NetMbpsRx > 0 || st.NetMbpsTx > 0 {
			net += fmt.Sprintf(" (cap %d/%d Mbps)", st.NetMbpsRx, st.NetMbpsTx)
		}
		disk := fmt.Sprintf("disk %s written", humanBytes(u.DiskWriteBytes))
		if st.DiskMbps > 0 || st.DiskIOPS > 0 {
			disk += " (capped)"
		}
		return barStyle.Render(strings.Join([]string{cpu, mem, net, disk}, " · "))
	}
	if m.receipt != nil {
		e := m.receipt
		return barStyle.Render(fmt.Sprintf(
			"final · %.2f CPU-seconds%s · peak RSS %s (VMM)%s · net %s in / %s out · disk %s written",
			e.CPUSeconds, quotaSuffix(*e), report.HumanKiB(e.PeakRSSKiB), capSuffix(e.MemMiB),
			humanBytes(e.NetInBytes), humanBytes(e.NetOutBytes), humanBytes(e.DiskWriteBytes)))
	}
	return dim.Render("  resources: waiting for the first sample…")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
