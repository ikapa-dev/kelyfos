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

// watchCmd is a live view of one sandbox.
//
// It reads the flight recorder and nothing else — it never opens a channel to
// the guest, never sends a command, and quitting it does not touch the sandbox.
// That is decision D7's line: viewers read the JSONL, managers change things,
// and this is a viewer.
func watchCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos watch", flag.ExitOnError)
	id := fs.String("session", "", "session id (default: the most recent)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos watch [flags]

A live view of one sandbox, built entirely from its flight recorder. It does not
talk to the guest and quitting it leaves the sandbox running.

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

type watchModel struct {
	session string
	path    string
	started time.Time
	program *tea.Program

	width, height int
	lines         []string

	// counters for the status line
	commands, failed, files, egressOK, egressBlocked, secrets int
	image, kernel, endReason                                  string
	bootMS                                                    int64

	// the resources lane: a live sample while the sandbox runs, and the
	// recorded receipt once it has stopped
	live, prev *usageMsg
	cpuPercent float64
	receipt    *recorder.Event
}

func (m *watchModel) Init() tea.Cmd { return tea.Batch(tick(), sampleUsage(m.session)) }

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
		return m, tea.Batch(tick(), sampleUsage(m.session))
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

func (m *watchModel) absorb(e recorder.Event) {
	if e.Type == recorder.TypeResourceSummary {
		ev := e
		m.receipt = &ev
	}
	ts := e.TS
	if len(ts) > 23 {
		ts = ts[11:23]
	}
	add := func(style lipgloss.Style, label, text string) {
		m.lines = append(m.lines, fmt.Sprintf("%s %s %s",
			dim.Render(ts), style.Render(fmt.Sprintf("%-9s", label)), text))
		// Keep only what can be shown; an unbounded slice in a long session is
		// a slow leak nobody would notice until it mattered.
		if len(m.lines) > 500 {
			m.lines = m.lines[len(m.lines)-500:]
		}
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
		m.commands++
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
			m.failed++
		}
		add(style, "exit", fmt.Sprintf("%d · %d ms", code, e.DurationMS))
	case recorder.TypeFileWrite:
		m.files++
		add(styleAmber, "write", fmt.Sprintf("%s · %d bytes", e.Path, e.Bytes))
	case recorder.TypeEgressAttempt:
		if e.Allowed != nil && *e.Allowed {
			m.egressOK++
			add(styleOK, "egress", fmt.Sprintf("%s:%d · %s", e.Host, e.Port, e.Mode))
		} else {
			m.egressBlocked++
			add(styleWarn, "BLOCKED", fmt.Sprintf("%s:%d · %s", e.Host, e.Port, e.Reason))
		}
	case recorder.TypeSecretUse:
		m.secrets++
		add(styleAmber, "secret", e.Name+" → "+e.Host)
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
