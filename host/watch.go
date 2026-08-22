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
}

func (m *watchModel) Init() tea.Cmd { return tick() }

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
		return m, tick()
	case eventMsg:
		m.absorb(recorder.Event(msg))
	}
	return m, nil
}

func (m *watchModel) absorb(e recorder.Event) {
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

	// Three lines of chrome: header, status, and the quit hint.
	lane := height - 4
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

	return header + "\n" + status + "\n" + strings.Repeat("─", min(width, 120)) + "\n" +
		body + "\n" + dim.Render("q to quit — the sandbox keeps running")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
