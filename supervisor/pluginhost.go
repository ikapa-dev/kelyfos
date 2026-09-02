package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ikapa-dev/kelyfos/internal/argsummary"
	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// The plugin runtime (E4-7).
//
// Each [[plugin]] is a child process speaking MCP over its own standard
// streams, launched from the read-only device E4-6 mounted. Its tools are
// advertised to the agent as <plugin>_<tool> alongside the built-in ones, and a
// call to one is forwarded and its answer returned unchanged.
//
// A plugin has exactly the powers of a malicious agent, and the sandbox already
// assumes the agent is malicious: same machine, same read-only root, same
// absent network. It inherits this process's environment, egress proxy
// included, because that is the single network policy surface and there is
// nothing here a plugin can reach that agent-written code could not have
// reached anyway (docs/mcp-surface.md §3.1).

// pluginToolName is the strictest constraint anything downstream of MCP
// imposes: the Anthropic Messages API's own, which excludes the dot that the
// MCP specification permits. A plugin's tool that cannot survive it is refused
// at boot rather than advertised and rejected later by somebody else's API
// (F-D36).
var pluginToolName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// pluginStartTimeout bounds the handshake. A plugin that has not answered
// initialize by then is not going to, and the sandbox must not wait on it.
const pluginStartTimeout = 20 * time.Second

// pluginCallTimeout bounds one forwarded call, so a plugin that stops answering
// costs its caller a clear error rather than a session that never returns.
const pluginCallTimeout = 120 * time.Second

type plugin struct {
	entry PluginEntry
	dir   string

	// One call at a time. MCP allows a client to have several in flight, and a
	// plugin is under no obligation to: serialising here is what makes every
	// plugin work rather than only the careful ones.
	mu     sync.Mutex
	cmd    *exec.Cmd
	in     io.WriteCloser
	stdout io.Closer
	out    *bufio.Scanner
	status chan syscall.WaitStatus
	next   int

	tools []mcp.Tool // namespaced, as the agent sees them
	dead  string     // why it stopped, "" while it is running
}

// thePlugins is what is running, in declaration order. Package-level for the
// reason theTeam is: there is one set per machine and the guest is told what it
// is rather than allowed to decide.
var (
	pluginsMu sync.RWMutex
	running   []*plugin
	// stopping is set when the machine is going down, so a plugin killed by
	// the shutdown is not reported as having crashed.
	stopping atomic.Bool
)

// startPlugins launches every plugin the manifest names and collects the tools
// they advertise. A plugin that fails to start is reported and skipped: one
// broken plugin must not cost the agent the other three, or the sandbox.
func startPlugins(entries []PluginEntry, rp *reaper, report func(proto.GuestEvent)) {
	for _, e := range entries {
		p, err := startPlugin(e, rp)
		if err != nil {
			logf("plugin %s did not start: %v", e.Name, err)
			report(proto.GuestEvent{
				V: proto.Version, Type: proto.GuestEventPluginCrash,
				Name: e.Name, Message: "did not start: " + err.Error(),
			})
			continue
		}
		pluginsMu.Lock()
		running = append(running, p)
		pluginsMu.Unlock()
		logf("plugin %s: %d tool(s)", e.Name, len(p.tools))
		go p.watch(rp, report)
	}
}

func startPlugin(e PluginEntry, rp *reaper) (*plugin, error) {
	dir := filepath.Join("/plugins", e.Name)
	p := &plugin{entry: e, dir: dir}

	cmd := exec.Command(e.Command, e.Args...)
	cmd.Dir = dir
	// Exactly the environment every command in this sandbox gets, egress
	// included. A plugin is not given a second network policy surface; it is
	// given the one the agent has (docs/mcp-surface.md §3.1).
	cmd.Env = defaultEnv
	// A plugin's stderr goes to the console, where a guest's diagnostics go. It
	// is not the protocol and must never be read as one.
	cmd.Stderr = prefixedLog("plugin " + e.Name)

	// The pipes are built by hand rather than with StdinPipe and StdoutPipe,
	// because those are closed by Cmd.Wait and nothing here calls Wait: this
	// process has exactly one waiter, the reaper, and a second wait4 would
	// steal the status from it.
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout = inR, outW

	status, err := rp.startAndRegister(cmd)
	if err != nil {
		for _, f := range []*os.File{inR, inW, outR, outW} {
			f.Close()
		}
		return nil, err
	}
	// The child holds its ends now; this side keeps only the ends it writes to
	// and reads from, so the plugin sees EOF when this closes and this sees EOF
	// when the plugin exits.
	inR.Close()
	outW.Close()

	p.cmd, p.in, p.status = cmd, inW, status
	p.stdout = outR
	sc := bufio.NewScanner(outR)
	sc.Buffer(make([]byte, 0, 64<<10), proto.MaxMCPLine)
	p.out = sc

	if err := p.handshake(); err != nil {
		_ = cmd.Process.Kill()
		<-status
		rp.forget(cmd.Process.Pid)
		inW.Close()
		outR.Close()
		return nil, err
	}
	return p, nil
}

// handshake initializes the plugin and reads its tool list once. The list is
// read at boot rather than per call: a tools/list on every request would put a
// round trip in front of every answer, and a plugin that changes its tools
// mid-session is a thing MCP has a notification for and KelyfOS does not need.
func (p *plugin) handshake() error {
	var init mcp.InitializeResult
	if err := p.call("initialize", map[string]any{
		"protocolVersion": mcp.ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "kelyfos-supervisor", "version": Version},
	}, &init, pluginStartTimeout); err != nil {
		return err
	}
	if err := p.notify("notifications/initialized"); err != nil {
		return err
	}
	var list mcp.ToolsListResult
	if err := p.call("tools/list", map[string]any{}, &list, pluginStartTimeout); err != nil {
		return err
	}
	for _, t := range list.Tools {
		full := p.entry.Name + "_" + t.Name
		if !pluginToolName.MatchString(full) {
			// Refused here rather than advertised: a name something downstream
			// will rewrite is worse than a missing tool, because the rewriting
			// is silent and can collide.
			logf("plugin %s: tool %q is not advertised — %q is not a name every client accepts",
				p.entry.Name, t.Name, full)
			continue
		}
		// The other half of the collision F-D36 argued about. The plugin name
		// rule stops one plugin's prefix from swallowing another's; this stops
		// a prefix from swallowing a built-in. A plugin called `read` exporting
		// `file` would otherwise put a second `read_file` in tools/list that
		// dispatch could never reach, because the built-in switch runs first —
		// two entries with one name, one of them dead (F-D49).
		if builtinTool(full) {
			logf("plugin %s: tool %q is not advertised — %q is a built-in tool of this sandbox, "+
				"and two tools with one name is worse than one missing tool",
				p.entry.Name, t.Name, full)
			continue
		}
		t.Name = full
		p.tools = append(p.tools, t)
	}
	return nil
}

// watch reports the plugin's death once, whenever it comes.
//
// The status comes from the reaper rather than from Cmd.Wait, which is what
// makes it the real exit status: with two waiters the first one to call wait4
// takes the status and the other gets "no child processes", which is a sentence
// about this process's plumbing rather than about the plugin.
func (p *plugin) watch(rp *reaper, report func(proto.GuestEvent)) {
	ws := <-p.status
	rp.forget(p.cmd.Process.Pid)
	why := describeExit(ws)
	p.mu.Lock()
	p.in.Close()
	p.stdout.Close()
	if p.dead == "" {
		p.dead = why
	}
	p.mu.Unlock()
	logf("plugin %s stopped: %s", p.entry.Name, why)
	if stopping.Load() {
		return
	}
	report(proto.GuestEvent{
		V: proto.Version, Type: proto.GuestEventPluginCrash,
		Name: p.entry.Name, Message: why,
	})
}

// notify sends a message with no id, which JSON-RPC forbids answering.
func (p *plugin) notify(method string) error {
	blob, err := json.Marshal(mcp.Notification{JSONRPC: "2.0", Method: method})
	if err != nil {
		return err
	}
	_, err = p.in.Write(append(blob, '\n'))
	return err
}

// call sends one request and reads its answer, skipping anything that is not
// it. Progress notifications from a plugin are ignored rather than forwarded:
// the agent asked this supervisor for a tool, and streaming a plugin's progress
// is E4-8's question, not this one's.
func (p *plugin) call(method string, params, result any, timeout time.Duration) error {
	p.next++
	id := json.RawMessage(fmt.Sprintf("%d", p.next))
	req := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  any             `json:"params,omitempty"`
	}{"2.0", id, method, params}
	blob, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := p.in.Write(append(blob, '\n')); err != nil {
		return err
	}

	type answer struct {
		line []byte
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		for {
			if !p.out.Scan() {
				err := p.out.Err()
				if err == nil {
					err = io.EOF
				}
				done <- answer{err: err}
				return
			}
			line := bytes.TrimRight(p.out.Bytes(), "\r")
			if len(line) == 0 {
				continue
			}
			var head struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal(line, &head); err != nil {
				done <- answer{err: err}
				return
			}
			if string(head.ID) != string(id) {
				continue
			}
			done <- answer{line: append([]byte(nil), line...)}
			return
		}
	}()

	select {
	case a := <-done:
		if a.err != nil {
			return a.err
		}
		var resp struct {
			Result json.RawMessage `json:"result"`
			Error  *mcp.Error      `json:"error"`
		}
		if err := json.Unmarshal(a.line, &resp); err != nil {
			return err
		}
		if resp.Error != nil {
			return errors.New(resp.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(resp.Result, result)
	case <-time.After(timeout):
		return fmt.Errorf("no answer to %s in %s", method, timeout)
	}
}

// pluginTools is what the plugins add to the agent's tool list.
func pluginTools() []mcp.Tool {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	var out []mcp.Tool
	for _, p := range running {
		p.mu.Lock()
		dead := p.dead
		p.mu.Unlock()
		// A dead plugin's tools stay listed and fail with a reason. Removing
		// them would leave an agent that had already read the list calling
		// something that no longer exists, told only "unknown tool" — which is
		// what a typo looks like, not what a crash looks like.
		_ = dead
		out = append(out, p.tools...)
	}
	return out
}

// findPluginTool resolves a namespaced name to the plugin that owns it.
//
// The prefix is matched against the declared names rather than split on the
// first underscore, because a tool name may contain underscores of its own and
// splitting would invent a plugin that does not exist.
func findPluginTool(name string) (*plugin, string, bool) {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	for _, p := range running {
		prefix := p.entry.Name + "_"
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		for _, t := range p.tools {
			if t.Name == name {
				return p, strings.TrimPrefix(name, prefix), true
			}
		}
	}
	return nil, "", false
}

// callPluginTool forwards one call and returns the plugin's answer unchanged,
// including isError — which belongs to the agent to read.
func callPluginTool(p *plugin, tool string, args json.RawMessage, report func(proto.GuestEvent)) *mcp.CallToolResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dead != "" {
		// The tools of a crashed plugin fail; the sandbox does not. exec still
		// works, the other plugins still work, and this says which case it is.
		return mcp.Errorf("plugin %s is no longer running (%s), so %s cannot be called. "+
			"Everything else in this sandbox is unaffected.", p.entry.Name, p.dead, tool)
	}
	started := time.Now()
	var res mcp.CallToolResult
	err := p.call("tools/call", mcp.CallToolParams{Name: tool, Arguments: args}, &res, pluginCallTimeout)
	outcome := "ok"
	if err != nil || res.IsError {
		outcome = "error"
	}
	report(proto.GuestEvent{
		V: proto.Version, Type: proto.GuestEventPluginCall,
		Name: p.entry.Name, Tool: tool, Outcome: outcome,
		DurationMS: time.Since(started).Milliseconds(),
		Args:       summarisePluginArgs(args),
	})
	if err != nil {
		return mcp.Errorf("plugin %s failed to answer %s: %v", p.entry.Name, tool, err)
	}
	return &res
}

// describeExit says what a status was, in the words a reader wants: the exit
// code, or the signal that ended it.
func describeExit(ws syscall.WaitStatus) string {
	switch {
	case ws.Signaled():
		// SIGTERM's String() is "terminated", which reads as a sentence
		// fragment rather than as a signal. The name is what a reader wants.
		return "killed by " + unix.SignalName(ws.Signal())
	case ws.ExitStatus() == 0:
		return "exited 0"
	default:
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	}
}

// maxPluginStderrLine bounds one console line from a plugin's stderr. A line
// longer than this is dropped with a note rather than kept: the console is a
// diagnostic surface, not a data channel, and a plugin cannot be allowed to
// wedge it — see prefixedLog.
const maxPluginStderrLine = 64 << 10

// prefixedLog turns a plugin's stderr into console lines that say whose they
// are, so a plugin complaining is distinguishable from the supervisor doing so.
//
// Every line is sanitised before it is written (audit 2026-09-01, A18): a
// plugin's stderr is untrusted output aimed at the operator's terminal, and
// without the sanitiser a plugin could write escape sequences — or a line that
// reads as the supervisor's own — onto the console the operator is reading.
// SafeText quotes a line carrying any control character whole, which is the
// right shape: the diagnostic survives, the escape does not.
//
// A stderr line longer than maxPluginStderrLine used to end the scanner for
// good (bufio.ErrTooLong is terminal) without draining the pipe, so the
// plugin's next stderr Write blocked on a reader that had gone away and the
// plugin wedged (audit 2026-09-01, L10). One shared bufio.Reader is the fix:
// the overlong line is noted and its tail skipped through its newline, a fresh
// scanner picks up from there, and every later line still reaches the console.
func prefixedLog(prefix string) io.Writer {
	r, w := io.Pipe()
	go func() {
		br := bufio.NewReader(r)
		for {
			sc := bufio.NewScanner(br)
			sc.Buffer(make([]byte, 0, 4<<10), maxPluginStderrLine)
			for sc.Scan() {
				logf("%s: %s", prefix, sanitizeConsoleLine(sc.Text()))
			}
			if !errors.Is(sc.Err(), bufio.ErrTooLong) {
				return
			}
			logf("%s: a stderr line longer than %d bytes was dropped", prefix, maxPluginStderrLine)
			if err := skipRestOfLine(br); err != nil {
				return
			}
		}
	}()
	return w
}

// skipRestOfLine drains br up to and including the next newline. The scanner
// that hit maxPluginStderrLine consumed only the head of the overlong line;
// its tail is still in the pipe, and the plugin is blocked writing the rest of
// it, so it has to be read out before the next line can be — otherwise the
// recovery would rebuild the scanner onto a pipe that never moves.
func skipRestOfLine(br *bufio.Reader) error {
	for {
		if _, err := br.ReadSlice('\n'); err != bufio.ErrBufferFull {
			return err
		}
	}
}

// sanitizeConsoleLine is the one place a plugin's own words reach the
// operator's console, so it is the one place the sanitiser runs.
func sanitizeConsoleLine(line string) string {
	return proto.SafeText(line)
}

// builtinTool reports whether a name is one the sandbox already answers.
//
// Read from the tool definitions rather than listed here, so a built-in added
// later is covered without anyone remembering this function exists. The team
// tools are included whether or not this sandbox is in a team: a name that would
// collide in a team is a name that must not be advertised out of one, or the
// same plugin would work in one sandbox and be silently short a tool in another.
func builtinTool(name string) bool {
	for _, t := range toolDefinitions() {
		if t.Name == name {
			return true
		}
	}
	for _, t := range teamToolDefinitions(true) {
		if t.Name == name {
			return true
		}
	}
	return false
}

// contentKeys, the size/line bounds, summarisePluginArgs and clipUTF8 all used
// to be declared here in full, byte-for-byte duplicated in
// host/servemcpaudit.go's summariseArgs and its own copy of every helper
// underneath it. They now live once, in internal/argsummary, which both this
// file and that one call — so an edit to the redaction or bounding rules can
// no longer land in one door's record and not the other's (F12).
//
// The bound still matters here for its own reason: the agent's arguments
// arrive on the MCP channel, whose frame limit is proto.MaxMCPLine — 16 MiB —
// and this summary leaves on the events channel, whose limit is proto.MaxLine,
// 1 MiB. proto.Writer.Write measures before it writes, so an oversized report
// is refused with ErrLineTooLong, and pumpEvents (supervisor/main.go) keeps a
// refused event as `pending` and sends it first on the next connection — where
// it is refused again, for as long as the machine runs.
var contentKeys = argsummary.ContentKeys

const (
	maxArgBytes   = argsummary.MaxArgBytes
	maxArgsBytes  = argsummary.MaxArgsBytes
	maxArrayBytes = argsummary.MaxArrayBytes
)

func summarisePluginArgs(raw json.RawMessage) string { return argsummary.Summarise(raw) }

func clipUTF8(s string, n int) string { return argsummary.ClipUTF8(s, n) }
