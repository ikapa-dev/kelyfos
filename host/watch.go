package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
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
	asJSON := fs.Bool("json", false,
		"print one snapshot of the digest — every counter, the policy and the topology (P7-10) — as JSON, "+
			"instead of opening the live view")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos watch [flags]

A live view of a sandbox, built entirely from its flight recorder. It does not
talk to the guest and quitting it leaves the sandbox running.

A team session shows one lane per agent — its commands, files, egress and what
it is consuming against its own caps — with the messages between agents in a
ticker underneath and the team's collective budget above. There is no flag for
it: a session whose events name agents is a team.

Two more panes sit behind that one (P7-7), reading the same fold: a map of
the declared topology, with any refusals seen so far and their fix lines, and
an agent sheet — each agent's declared caps beside what it has actually done.

  1, v             activity pane (the default, above)
  2, m             map pane — declared topology
  3, s             agent sheet — caps beside live counters
  q, esc, ctrl-c   quit

--json (P7-10) skips all of the above: it reads the chain recorded so far,
once, and prints internal/digest's own Snapshot shape — the same aggregate
every pane above already reads — for a script to consume instead of a person
to watch. docs/teams.md §8.5 documents the shape.

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

	if *asJSON {
		return watchJSON(path)
	}

	m := &watchModel{session: sessionID, path: path, started: time.Now()}
	// The alt screen is a property of the view in v2, not an option on the
	// program: set once in View() rather than asked for here (F-D51).
	p := tea.NewProgram(m)
	m.program = p
	go m.tail()
	_, err = p.Run()
	return err
}

// watchJSON is `kelyfos watch --json`: a one-shot snapshot of the session's
// digest, printed once and exited, rather than the live TUI. It never
// live-tails — a caller who wants the current state re-runs it, the same
// "once" `kelyfos log --json` has always offered next to `--follow --json`
// for "as it happens".
//
// Built with a zero-value digest.Digest, the same shape watchModel's own d
// field starts as (never digest.New()), so this snapshot has no Timeline for
// exactly the reason the live view never keeps one: KeepTimeline's own doc
// comment says why retaining it is the unbounded growth a session with no
// natural end must not pay for. A team still up when this runs is read as it
// stands at that moment, not followed.
func watchJSON(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no flight recorder at %s: %w", path, err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		return err
	}
	var d digest.Digest
	for _, e := range events {
		d.Absorb(e)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(d.Snapshot())
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

// lane is one agent's column in a team view: its own recent activity and its
// own reading of what it is consuming, both readings of state that lives
// elsewhere — the styled lines are this view's own, and the counters and the
// usage receipt are internal/digest's, read off m.d.Agents by name rather than
// duplicated here (P7-1).
//
// A team is one session (E2-7), so all of this comes out of one file — the
// lane is a split of the chain by the `agent` field, not a second source of
// truth.
type lane struct {
	name  string
	lines []string

	live, prev *usageMsg
	cpuPercent float64
}

// pane selects which of watch's three panes render() draws. activity is the
// default — everything this view showed before P7-7 — and map/sheet are
// P7-7's addition: the declared shape of the run (map) and each agent's
// declared caps beside what it has actually done so far (sheet), both read
// off m.d rather than kept a second time here.
type pane int

const (
	paneActivity pane = iota
	paneMap
	paneSheet
)

type watchModel struct {
	session string
	path    string
	started time.Time
	program *tea.Program

	width, height int
	lines         []string
	// pane is which of the three views render() draws. Starts on activity —
	// what this view always showed — so opening `kelyfos watch` looks
	// exactly as it did before P7-7 until a key asks for something else.
	pane pane
	// refusals is a bounded, live-appended list of denial fix lines —
	// everything refusalLine recognises across team.refused, team.store and
	// team.spawn — the map pane's "now what" section. Kept here rather than
	// read off m.d.Timeline because a live watch's Digest deliberately does
	// not retain one (KeepTimeline is false by default): the same
	// unbounded-growth reason that keeps it off applies to this list too, so
	// it is capped the same way MaxDistinctKeys caps internal/digest's own
	// collections.
	refusals []string
	// refusalsTruncated is set once pushRefusal has dropped an entry to stay
	// under maxRefusalLines, so the pane can say its list is a tail rather
	// than the whole story.
	refusalsTruncated bool

	// d is the one fold (internal/digest), absorbed live as each event
	// arrives off the tail of the running session — no call to digest.New
	// needed, since a zero-value Digest is safe to absorb into. It carries
	// every counter, the team's messages and refusals, the session header
	// (image, kernel, boot time, end reason) and the usage receipts, so this
	// model no longer keeps its own copies of any of them.
	d digest.Digest

	// The team view. lanes holds each agent's own styled buffer; order is
	// first-appearance order, which is boot order, so the columns read like
	// the file the user wrote. A lane is minted the moment an agent is
	// *seen* — by an event or by a live sample, whichever comes first, which
	// is why this is tracked here rather than read off d.AgentOrder: that
	// slice is chain-derived only, and a sample is a reading, not a record
	// (F-D14). Empty until then, at which point the view becomes a team
	// view — there is no flag to set and nothing to ask the user.
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

	// the resources lane: a live sample while the sandbox runs, and the
	// recorded receipt once it has stopped
	live, prev *usageMsg
	cpuPercent float64
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
	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "1", "v":
			m.pane = paneActivity
		case "2", "m":
			m.pane = paneMap
		case "3", "s":
			m.pane = paneSheet
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

// lane returns an agent's lane, creating it the first time that agent is seen
// — by an event or by a live sample, whichever happens first. Creation order
// is the lane order, and the first lane created is what turns this into a
// team view.
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

// agentCounters is what an agent's lane has done, read from the fold rather
// than kept twice — nil-safe, because a lane can exist here (minted by a live
// sample, see lane above) before the chain has recorded anything for it.
func (m *watchModel) agentCounters(name string) digest.Counters {
	if a := m.d.Agents[name]; a != nil {
		return a.Counters
	}
	return digest.Counters{}
}

// agentReceipt is an agent's usage.receipt, or nil before one has been
// written — the same nil-safety agentCounters needs, for the same reason.
func (m *watchModel) agentReceipt(name string) *recorder.Event {
	if a := m.d.Agents[name]; a != nil {
		return a.Receipt
	}
	return nil
}

// pushRefusal appends one denial fix line to the live, bounded list the map
// pane's "refused since boot" section reads (see watchModel.refusals). Past
// maxRefusalLines the oldest line is dropped and refusalsTruncated is set,
// so a hostile session looping a refused call cannot grow this list without
// bound — and the pane says so, rather than silently showing a partial list
// as though it were complete (RENDER checklist: "bounded, and saying so
// when it truncates").
func (m *watchModel) pushRefusal(line string) {
	m.refusals = append(m.refusals, line)
	if len(m.refusals) > maxRefusalLines {
		m.refusals = m.refusals[len(m.refusals)-maxRefusalLines:]
		m.refusalsTruncated = true
	}
}

// agentPolicy is an agent's session.policy, or nil before one has been
// absorbed — the same nil-safety agentReceipt needs. Outside a team, name is
// the session itself and the agentless m.d.Policy is what applies (P7-7).
func (m *watchModel) agentPolicy(name string) *recorder.Event {
	if a := m.d.Agents[name]; a != nil && a.Policy != nil {
		return a.Policy
	}
	if name == m.session {
		return m.d.Policy
	}
	return nil
}

// bound keeps a line buffer to what can ever be shown. An unbounded slice in a
// long session is a slow leak nobody would notice until it mattered.
func bound(lines []string, max int) []string {
	if len(lines) > max {
		return lines[len(lines)-max:]
	}
	return lines
}

// absorb folds one event and draws the line it produces. The fold itself —
// which counter this bumps, whether this is a refusal, which agent's bucket
// it belongs to — is internal/digest's job now (P7-1): this method reads back
// what Absorb decided (entry.Refused, entry.Text for a decoded command.output
// chunk) rather than recomputing it, and keeps only what is genuinely this
// view's own: the styled text and which buffer it goes in.
func (m *watchModel) absorb(e recorder.Event) {
	// The fold sees the record as written; the view sees it cleaned. Absorb
	// first, then sanitise, so internal/digest's counters and keys are of the
	// chain rather than of this view's rendering of it.
	entry := m.d.Absorb(e)
	e = safeEvent(e)

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

	// Every value below came out of the chain, which means a guest, a
	// teammate or a tampered file chose it, and lipgloss emits exactly what it
	// is handed — fitStyled trims runes and is not a sanitiser. `kelyfos log`
	// and `kelyfos view` have routed these through proto.SafeText since P6-28;
	// this view routed none of them until P7-17/F20, so an OOM victim named
	// "\x1b[2J" cleared the operator's screen mid-run and repainted whatever
	// it liked. safe is named short because it is used on every line here.
	safe := proto.SafeText

	switch e.Type {
	case recorder.TypeSessionStart:
		add(styleMuted, "session", "start "+safe(e.Image)+" · "+safe(e.Arch))
	case recorder.TypeSessionReady:
		add(styleOK, "ready", fmt.Sprintf("%d ms · kernel %s", e.BootMS, safe(e.Kernel)))
	case recorder.TypeSessionEnd:
		add(styleMuted, "session", "end "+safe(e.Reason))
	case recorder.TypeCommandStart:
		add(styleCmd, "$", safe(strings.Join(e.Cmd, " ")))
	case recorder.TypeCommandOutput:
		// entry.Text is the base64 payload, already decoded once by
		// digest.Absorb — this view no longer decodes it a second time.
		// proto.SafeBody rather than safe, for the same reason the replay
		// uses it: output is legitimately multi-line and legitimately
		// coloured, and quoting the whole chunk would cost more than it
		// bought. Applied to the whole chunk before the split, so a sequence
		// straddling a newline cannot be reassembled by the terminal.
		for _, l := range strings.Split(strings.TrimRight(proto.SafeBody(entry.Text), "\n"), "\n") {
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
		if entry.Refused {
			style = styleWarn
		}
		add(style, "exit", fmt.Sprintf("%d · %d ms", code, e.DurationMS))
	case recorder.TypeFileWrite:
		add(styleAmber, "write", fmt.Sprintf("%s · %d bytes", safe(e.Path), e.Bytes))
	case recorder.TypeEgressAttempt:
		// from names who connected, which only a foreign_peer refusal carries
		// — and it carries nothing else, so without this the line reads
		// `BLOCKED :0 · foreign_peer` (P7-17/F9, rendered in F20).
		from := ""
		if e.Peer != "" {
			from = " from " + safe(e.Peer)
		}
		if !entry.Refused {
			add(styleOK, "egress", fmt.Sprintf("%s:%d · %s%s", safe(e.Host), e.Port, safe(e.Mode), from))
		} else {
			add(styleWarn, "BLOCKED", fmt.Sprintf("%s:%d · %s%s", safe(e.Host), e.Port, safe(e.Reason), from))
		}
	case recorder.TypeSecretUse:
		add(styleAmber, "secret", safe(e.Name)+" → "+safe(e.Host))
	case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
		// Named so the two ends are both visible: an ask points forward, a
		// reply back, and a refusal says so before it says anything else.
		arrow := "→"
		if e.Kind == "reply" {
			arrow = "←"
		}
		body := fmt.Sprintf("%s %s %s  %s · %d bytes", safe(e.Agent), arrow, safe(e.Peer), safe(e.Kind), e.Bytes)
		if entry.Refused {
			tick(styleWarn.Render("REFUSED ") + body + dim.Render("  ("+safe(e.Reason)+")"))
			if l, ok := refusalLine(e); ok {
				m.pushRefusal(l)
			}
			break
		}
		tick(styleMuted.Render("msg     ") + body)
	case recorder.TypeTeamStore:
		// A store access is something one agent did, so it goes in that
		// agent's lane — and also in the ticker when it was refused, because a
		// refusal is the thing a watcher is watching for.
		style, label := styleAmber, "store"
		if entry.Refused {
			style, label = styleWarn, "DENIED"
			tick(styleWarn.Render("DENIED  ") +
				fmt.Sprintf("%s %s %s", safe(e.Agent), safe(e.Kind), safe(e.Peer)) +
				dim.Render("  ("+safe(e.Reason)+")"))
			if l, ok := refusalLine(e); ok {
				m.pushRefusal(l)
			}
		}
		add(style, label, fmt.Sprintf("%s %s", safe(e.Kind), safe(e.Peer)))
	case recorder.TypeTeamSpawn:
		if entry.Refused {
			tick(styleWarn.Render("REFUSED ") + safe(e.Agent) + " may not spawn" +
				dim.Render("  ("+safe(e.Reason)+")"))
			if l, ok := refusalLine(e); ok {
				m.pushRefusal(l)
			}
			break
		}
		tick(styleOK.Render("spawn   ") + fmt.Sprintf("%s %s by %s", safe(e.Kind), safe(e.Peer), safe(e.Agent)))
	case recorder.TypeResourceOOM:
		add(styleWarn, "OOM", fmt.Sprintf("%s (pid %d) holding %s",
			safe(e.Comm), e.PID, report.HumanKiB(e.RSSKiB)))
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

// View returns a tea.View rather than a string in v2, which is what carries the
// alt-screen flag: the terminal's mode is now something the view declares each
// frame rather than something the program was started with.
func (m *watchModel) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

func (m *watchModel) render() string {
	width := m.width
	if width < 40 {
		width = 80
	}
	height := m.height
	if height < 10 {
		height = 24
	}

	// P7-7's two added panes render the same regardless of whether this turns
	// out to be a team or a single sandbox — both read m.d, and both say so
	// when there is nothing yet to draw.
	switch m.pane {
	case paneMap:
		return m.mapPane(width, height)
	case paneSheet:
		return m.sheetPane(width, height)
	}

	// The chain decides which view this is: a session that carries agents is a
	// team, and there is nothing to ask the user.
	if len(m.order) > 0 {
		return m.teamView(width, height)
	}

	// EndReason, Image and Arch all come off the chain, and the chain carries
	// what a guest reported: Image and Arch are host-set on this door, but the
	// digest reads them out of a session.start that a chain from anywhere may
	// have written, and EndReason is a free-text field on two of its branches.
	// host/view.go sanitises the same three when it renders the same header;
	// this one did not, which is the shape F20 is about — one renderer cleaned
	// and the next one not (P7-17/C).
	state := "running"
	if m.d.EndReason != "" {
		state = "stopped (" + proto.SafeText(m.d.EndReason) + ")"
	}
	header := fmt.Sprintf("%s  sandbox %s  %s  %s",
		titleStyle.Render("KelyfOS"), proto.SafeText(m.session),
		proto.SafeText(m.d.Image)+" · "+proto.SafeText(m.d.Arch), state)

	status := barStyle.Render(fmt.Sprintf(
		"uptime %s · boot %d ms · %d commands (%d failed) · %d files · egress %d ok / %d blocked · %d secret uses",
		time.Since(m.started).Truncate(time.Second), m.d.BootMS,
		m.d.Session.Commands, m.d.Session.Failed, m.d.Session.Files,
		m.d.Session.EgressOK, m.d.Session.EgressBlocked, m.d.Session.Secrets))

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
		body + "\n" + dim.Render(paneHint+" — the sandbox keeps running")
}

// paneHint is the key legend every pane's last line ends with — one place so
// the three panes cannot describe their own switching differently.
const paneHint = "1 activity · 2 map · 3 agent sheet · q to quit"

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
	if m.d.EndReason != "" {
		state = "stopped (" + proto.SafeText(m.d.EndReason) + ")"
	}
	header := fmt.Sprintf("%s  team session %s  %d agents  %s",
		titleStyle.Render("KelyfOS"), proto.SafeText(m.session), n, state)
	agentTot := m.d.AgentTotals()
	status := barStyle.Render(fmt.Sprintf(
		"uptime %s · %d messages · %d refused · %d commands (%d failed) · egress %d ok / %d blocked",
		time.Since(m.started).Truncate(time.Second),
		m.d.Messages, m.d.AllRefusals(), agentTot.Commands, agentTot.Failed,
		agentTot.EgressOK, agentTot.EgressBlocked))
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
				merged = append(merged, dim.Render("["+proto.SafeText(name)+"]")+" "+ln)
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
		dim.Render(paneHint+" — the team keeps running")
}

// laneBlock renders one agent's column as exactly laneH+2 lines of exactly
// laneW columns: a name, a resource line, then its activity.
//
// The width is fixed here rather than left to the terminal, because columns
// that are only usually the same width are not columns.
func (m *watchModel) laneBlock(l *lane, laneW, laneH int) []string {
	out := make([]string, 0, laneH+2)
	// The lane's heading is an agent name off the chain — the sheet pane has
	// routed it through SafeText since it was written; this one had not
	// (P7-17/F20).
	out = append(out, titleStyle.Render(fit(proto.SafeText(l.name), laneW)))
	out = append(out, barStyle.Render(fit(l.laneUsage(m.agentReceipt(l.name)), laneW)))
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
// receipt is the agent's resource.summary, read out of the fold by the caller
// (watchModel.agentReceipt) rather than kept a second time here.
func (l *lane) laneUsage(receipt *recorder.Event) string {
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
	if receipt != nil {
		return fmt.Sprintf("final %.1fs cpu, peak %s",
			receipt.CPUSeconds, report.HumanKiB(receipt.PeakRSSKiB))
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

// fitToBudget returns at most budget lines: all of lines when they already
// fit, or the first budget-1 lines plus note when they do not — so the
// total is never more than budget, note included, rather than budget lines
// of content plus one more for the note on top (an off-by-one a review
// caught: the old per-pane logic added its truncation line after already
// selecting a full budget's worth of content, so every pane emitted one
// line more than its own height every time it truncated). budget <= 0
// returns nil.
func fitToBudget(lines []string, budget int, note string) []string {
	if budget <= 0 {
		return nil
	}
	if len(lines) <= budget {
		return lines
	}
	if budget == 1 {
		return []string{note}
	}
	out := append([]string{}, lines[:budget-1]...)
	return append(out, note)
}

// mapPane draws the declared topology (P7-7): a team's, once its
// team.topology has landed, joined against every agent's own session.policy
// for the domains and secrets each one reaches — the exact conversion
// `kelyfos team ps --graph` uses (host/teamgraph.go's buildGraphInput), so a
// live map and a one-shot one never disagree about what the team declared.
// Outside a team, a single sandbox's own session.policy draws a one-node map
// of what that machine itself was permitted to reach.
//
// The refusals (and any notes on what this live view cannot know — see
// spawnedAgentsNotInTopology and the store-enabled caveat) are laid out
// separately from the graph body and guaranteed their own share of the
// height budget below, rather than appended to one string and truncated
// from the top: a review found that on a real 5-agent team under a 120x24
// terminal, the refusals section — the whole point of "now what" — was the
// first thing cut, along with the edge table and the pane-switching hint.
func (m *watchModel) mapPane(width, height int) string {
	header := fmt.Sprintf("%s  map — declared topology  session %s",
		titleStyle.Render("KelyfOS"), m.session)

	var graphBody string
	var notes []string
	switch {
	case m.d.Topology != nil:
		agents := graphAgentsFromTopology(m.d.Topology, m.d.Agents)
		store := graphStoreFromTopology(m.d.Topology)
		// See buildGraphInput's own doc comment: team.topology carries no
		// "store enabled" flag independent of its rule count, so this is a
		// documented best-effort rather than a silent gap — the note below
		// says so when the rule list is empty.
		storeEnabled := len(store) > 0
		in, err := buildGraphInput(agents, m.d.Topology.Edges, store, storeEnabled)
		if err != nil {
			graphBody = dim.Render("  " + err.Error())
			break
		}
		var b strings.Builder
		title := fmt.Sprintf("%d agents, %d edges", len(agents), len(in.Edges))
		if rerr := renderTeamGraph(&b, in, title); rerr != nil {
			graphBody = dim.Render("  " + rerr.Error())
			break
		}
		graphBody = b.String()
		if !storeEnabled {
			notes = append(notes, "note: no store rule recorded, and the chain cannot say whether "+
				"[team.store] is enabled with none — if it is, every key is team-wide by default and "+
				"would not appear above (P7-3 recorder gap)")
		}
		if extra := spawnedAgentsNotInTopology(m.d.Topology, m.d.Agents); len(extra) > 0 {
			notes = append(notes, fmt.Sprintf("+%d agent(s) spawned at runtime, not in the topology "+
				"declared at boot above: %s", len(extra), safeJoinNames(extra, maxSpawnedNamesShown)))
		}
	case m.d.Policy != nil:
		agents := []graphAgent{{Name: m.session, Allow: m.d.Policy.Allow, Secrets: m.d.Policy.Secrets}}
		in, err := buildGraphInput(agents, nil, nil, false)
		if err != nil {
			graphBody = dim.Render("  " + err.Error())
			break
		}
		var b strings.Builder
		_ = renderTeamGraph(&b, in, "one machine, its declared domains and secrets")
		graphBody = b.String()
	default:
		graphBody = dim.Render("  waiting for session.policy / team.topology to be recorded…")
	}

	var refusalLines []string
	if len(m.refusals) > 0 {
		refusalLines = append(refusalLines, "refused since boot")
		for _, l := range m.refusals {
			for _, ln := range strings.Split(l, "\n") {
				refusalLines = append(refusalLines, "  "+ln)
			}
		}
		if m.refusalsTruncated {
			refusalLines = append(refusalLines, dim.Render(fmt.Sprintf(
				"  … only the most recent %d refusals are kept; earlier ones were dropped", maxRefusalLines)))
		}
	}
	for _, n := range notes {
		refusalLines = append(refusalLines, dim.Render("  "+n))
	}

	// Chrome is header + rule + hint = 3 lines. Refusals/notes are
	// guaranteed up to half of what remains — their own size if that is
	// less — before the graph body gets whatever is left, so a short
	// refusal list is never starved by a long graph.
	budget := height - 3
	if budget < 1 {
		budget = 1
	}
	refusalBudget := len(refusalLines)
	if half := budget / 2; refusalBudget > half && half > 0 {
		refusalBudget = half
	}
	if refusalBudget > budget {
		refusalBudget = budget
	}
	graphBudget := budget - refusalBudget

	shownGraph := fitToBudget(strings.Split(graphBody, "\n"), graphBudget,
		dim.Render("  … more than fits this window; resize to see the rest"))
	shownRefusals := fitToBudget(refusalLines, refusalBudget,
		dim.Render("  … more than fits this window; see `kelyfos team ps --graph`"))

	all := make([]string, 0, len(shownGraph)+len(shownRefusals))
	all = append(all, shownGraph...)
	all = append(all, shownRefusals...)

	return header + "\n" + strings.Repeat("─", min(width, 120)) + "\n" +
		strings.Join(all, "\n") + "\n" + dim.Render(paneHint)
}

// sheetPane draws the agent sheet (P7-7): one row per agent with its
// declared caps and allowlist size beside what it has actually done so far
// — the declared and the aggregate, side by side, read off m.d rather than
// kept a second time here. Outside a team it draws one row for the sandbox
// itself.
func (m *watchModel) sheetPane(width, height int) string {
	header := fmt.Sprintf("%s  agent sheet  session %s",
		titleStyle.Render("KelyfOS"), m.session)

	names := m.order
	if len(names) == 0 {
		names = []string{m.session}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-18s %-10s %-16s %6s %6s %6s %8s %8s %6s\n",
		"AGENT", "SANDBOX", "CAPS", "ALLOW", "CMD", "FAIL", "EGR-OK", "EGR-BLK", "SECR")
	for _, name := range names {
		c := m.agentCounters(name)
		policy := m.agentPolicy(name)
		sandboxID, caps, allow := "—", "—", "—"
		if policy != nil {
			caps = fmt.Sprintf("%dc/%dM/%d%%", policy.VcpuCount, policy.MemMiB, policy.CPUQuota)
			allow = strconv.Itoa(len(policy.Allow))
		}
		if t := m.d.Topology; t != nil {
			for _, a := range t.Agents {
				if a.Name == name {
					sandboxID = a.Sandbox
				}
			}
		} else if name == m.session {
			sandboxID = m.session
		}
		fmt.Fprintf(&b, "%-18s %-10s %-16s %6s %6d %6d %8d %8d %6d\n",
			fit(proto.SafeText(name), 18), fit(proto.SafeText(sandboxID), 10), caps, allow,
			c.Commands, c.Failed, c.EgressOK, c.EgressBlocked, c.Secrets)
	}

	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	budget := height - 3
	if budget < 1 {
		budget = 1
	}
	shown := fitToBudget(lines, budget,
		dim.Render("  … more agents than fit this window; resize to see the rest"))

	return header + "\n" + strings.Repeat("─", min(width, 120)) + "\n" +
		strings.Join(shown, "\n") + "\n" + dim.Render(paneHint)
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
	if m.d.Receipt != nil {
		e := m.d.Receipt
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
