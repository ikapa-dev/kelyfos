package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/argsummary"
	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// The outward audit lane (E4-4).
//
// Every tool call an outside client makes is two events in the server's own
// flight recorder: mcp.host.call and mcp.host.result. Without them the record
// would say "an agent ran a command in a sandbox" and would not say "an agent
// decided to create a sandbox with these limits", and the second is the part a
// reader most wants when something has gone wrong (docs/mcp-surface.md §2.5).
//
// They live in the server's session rather than in each sandbox's, because the
// calls that matter most belong to no sandbox at the moment they are made: the
// one that chose a machine's limits, before the machine exists, and every call
// that was refused, which never gets one. Each sandbox's own chain says how it
// was reached — `via: serve-mcp` on its events, and the server's session id in
// its session.start — so a reader can go from either to the other.

// contentKeys, the size/line bounds, summariseArgs and clipUTF8 all used to be
// declared here in full, byte-for-byte duplicated in
// supervisor/pluginhost.go's summarisePluginArgs and its own copy of every
// helper underneath it. They now live once, in internal/argsummary, which
// both this file and that one call — so an edit to the redaction or bounding
// rules can no longer land in one door's record and not the other's (F12).
var contentKeys = argsummary.ContentKeys

const (
	maxArgBytes   = argsummary.MaxArgBytes
	maxArgsBytes  = argsummary.MaxArgsBytes
	maxArrayBytes = argsummary.MaxArrayBytes
)

// summariseArgs renders a call's arguments for the record. The logic lives in
// internal/argsummary now; this is the name the rest of this file calls.
func summariseArgs(raw json.RawMessage) string { return argsummary.Summarise(raw) }

// clipUTF8 cuts s to at most n bytes without leaving half a rune at the end.
// Also internal/argsummary's now — kept as a local name because clipField
// below uses it on fields argsummary has no reason to know about.
func clipUTF8(s string, n int) string { return argsummary.ClipUTF8(s, n) }

// clipField bounds one of the record's identifier fields.
//
// The tool name and the sandbox id are copied out of the client's frame into
// the event verbatim, and nothing has checked either one: auditCall runs before
// dispatchTool, so a name no tool answers to still becomes a line, and the
// sandbox id is recorded whether or not this server has such a sandbox — which
// is deliberate, and is the reason it cannot be trusted to be short. Nothing
// legitimate is touched: the longest tool name this server answers is
// `sandbox_write_file`, and a sandbox id is eight hex digits.
func clipField(s string) string {
	if len(s) <= maxArgBytes {
		return s
	}
	return fmt.Sprintf("%s…(%d bytes)", clipUTF8(s, maxArgBytes), len(s))
}

// argSandbox is the sandbox a call names, when it names one. It is a lane in
// the transcript rather than a lookup: the id is recorded whether or not this
// server has such a sandbox, because a call naming one it does not have is
// itself worth reading.
func argSandbox(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var a struct {
		Sandbox string `json:"sandbox"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return ""
	}
	// Bounded here rather than at the two places the id is written, because
	// recording an id this server has never heard of is the point of the lane
	// and the caller picks the bytes.
	return clipField(a.Sandbox)
}

// openAudit gives the server its own session. A serve-mcp process is a session
// in the same sense a `kelyfos run` is: it starts, it does things, it ends, and
// the record of it outlives it.
//
// P7-13: this session names no sandbox's own run directory and no sandbox
// ever records it as its own Session, so `kelyfos sessions prune`/`erase`
// had no way to tell this chain apart from an ordinary, long-idle, safe-to-
// remove one — live-reproduced as a silent, unrecoverable prune of a
// still-running process's own audit trail. The marker file below is this
// process's own liveness signal, in its own namespace (host/sessions.go's
// auditMarkerDir/hasLiveAuditMarker); a leftover one after a crash is the
// same accepted false positive a leftover sandbox run directory already is.
func (s *hostServer) openAudit() error {
	id, err := sandbox.NewID()
	if err != nil {
		return err
	}
	rec, err := recorder.Open(sandbox.Root(), id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(auditMarkerDir(), 0o700); err != nil {
		_ = rec.Close()
		return fmt.Errorf("marking this session live: %w", err)
	}
	if err := os.WriteFile(auditMarkerPath(id), nil, 0o600); err != nil {
		_ = rec.Close()
		return fmt.Errorf("marking this session live: %w", err)
	}
	s.auditID, s.audit = id, rec
	s.auditStopped = make(chan struct{})
	go s.watchAudit(rec, s.auditStopped)
	return rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Arch: s.arch, Kelyfos: Version,
		Argv: s.argv, Reason: recorder.ReasonServeMCP,
	})
}

// stderr is where this server's own lines to the operator go.
func (s *hostServer) stderr() io.Writer {
	if s.errw != nil {
		return s.errw
	}
	return os.Stderr
}

// watchAudit says, as soon as it happens, that this server's own chain has
// stopped (P7-17/A2).
//
// The refusal in callTool is the guarantee — it is synchronous and cannot be
// raced — and this is only about WHEN the operator hears. serve-mcp is idle
// between calls, sometimes for hours, so without this the first sign that the
// disk filled would be a refused tool call much later. The same shape
// watchRecorder uses for a box, minus the teardown: there is no machine here to
// bring down, and the sandboxes this server owns have chains and watchers of
// their own.
func (s *hostServer) watchAudit(rec *recorder.Recorder, stopped <-chan struct{}) {
	select {
	case <-stopped:
		return
	case <-rec.Broken():
	}
	s.sayAuditBroke(rec)
}

// sayAuditBroke prints the epitaph once, however many times it is reached: the
// watcher and every refused tool call both arrive here.
func (s *hostServer) sayAuditBroke(rec *recorder.Recorder) {
	s.auditSaid.Do(func() {
		seq, err := rec.Failure()
		fmt.Fprintf(s.stderr(),
			"kelyfos: this server's own flight recorder stopped at event %d: %v\n"+
				"kelyfos: refusing every tool call — a call nobody records is one this server "+
				"does not make.\n"+
				"kelyfos: the sandboxes already running keep their own chains; restart "+
				"serve-mcp once there is room to write.\n", seq, err)
	})
}

// refuseIfUnrecorded is the gate callTool runs before it dispatches anything,
// and nil is the ordinary answer (P7-17/A2).
//
// It reads Failure() rather than selecting on Broken(), because the question
// here is not "has it broken by now" but "is it broken at the moment this call
// would be recorded" — and the answer has to be the same for the check and for
// the append that follows it.
func (s *hostServer) refuseIfUnrecorded() *mcp.CallToolResult {
	rec := s.audit
	if rec == nil {
		return nil
	}
	seq, err := rec.Failure()
	if err == nil {
		return nil
	}
	s.sayAuditBroke(rec)
	return mcp.Errorf("this KelyfOS server's flight recorder stopped at event %d (%v), so it "+
		"is refusing every tool call: a call nobody records is one this server does not make. "+
		"Sandboxes already running keep their own records. Free space where the record is "+
		"written, then restart the server.", seq, err)
}

func (s *hostServer) closeAudit() {
	if s.audit == nil {
		return
	}
	if s.auditStopped != nil {
		close(s.auditStopped)
		s.auditStopped = nil
	}
	// EndBroken first, and it is a no-op on an intact recorder (P7-17/A2). It
	// was missing here while every other teardown in the CLI had it through
	// endSession: on a broken recorder the ordinary session.end below is
	// refused like every other append, so without this the chain simply stopped
	// mid-session with nothing saying why. By now the process is on its way out
	// and whatever was holding the disk may have let go, which is the whole
	// reason the recorder offers a second attempt.
	_ = s.audit.EndBroken()
	_ = s.audit.Append(recorder.Event{
		Type: recorder.TypeSessionEnd, Reason: "shutdown",
		DurationMS: s.audit.Since().Milliseconds(),
	})
	_ = s.audit.Close()
	_ = os.Remove(auditMarkerPath(s.auditID))
	s.audit = nil
}

// auditCall records a call as it arrives and returns the function that records
// what it came back with. A refused call is recorded exactly like a permitted
// one: a ceiling nobody can see being enforced is a ceiling nobody can audit.
func (s *hostServer) auditCall(p *mcp.CallToolParams) func(*mcp.CallToolResult) {
	if s.audit == nil {
		return func(*mcp.CallToolResult) {}
	}
	call := fmt.Sprintf("c%d", time.Now().UnixNano())
	box := argSandbox(p.Arguments)
	// The name is the client's string, and this runs before dispatch decides
	// whether it is a tool at all.
	name := clipField(p.Name)
	_ = s.audit.Append(recorder.Event{
		Type: recorder.TypeMCPHostCall, Call: call, Name: name,
		Agent: box, Args: summariseArgs(p.Arguments),
	})
	started := time.Now()
	return func(res *mcp.CallToolResult) {
		ev := recorder.Event{
			Type: recorder.TypeMCPHostResult, Call: call, Name: name,
			Agent: box, Outcome: "ok", DurationMS: time.Since(started).Milliseconds(),
		}
		// A call that created a sandbox names it only in its answer, and that
		// is the one call whose lane matters most.
		if ev.Agent == "" {
			ev.Agent = resultSandbox(res)
		}
		if res != nil && res.IsError {
			ev.Outcome = "error"
			ev.Error = &recorder.EvError{Kind: "tool", Message: resultErrorShape(res)}
		}
		_ = s.audit.Append(ev)
	}
}

// resultErrorShape says how a tool call failed without copying any of what it
// returned (F12).
//
// This used to be firstLine(res.Content[0].Text), and the reason given for
// leaving error.message out of the erasure was that it holds "a
// system-generated string ... with no established precedent for holding raw
// guest content". The precedent was two files away: sandbox_exec builds its
// tool result out of res.Stdout (servemcptools.go's toolExec), and IsError is
// set from the guest's own exit code — so every failed command in a serve-mcp
// session left its first line of output in a field an erasure did not touch.
//
// This function cannot tell a host-written refusal from a guest's stdout;
// both arrive as Content[0].Text and nothing in the result distinguishes them.
// So it copies neither, and records the shape instead: the exit status the
// guest process returned — a number the chain already keeps, unredacted, in
// command.exit's own `code` — or, when there is no exit status to report, the
// size of the content it declined to hold. Sizing what must not be recorded is
// the rule summariseArgs already applies to every argument of every tool.
//
// What the failure was is not lost. It is in the sandbox's own chain, in the
// command.output events that carry the same bytes and that an erasure DOES
// redact, which is where output belongs; the outward lane records that the
// call failed, which tool, with which arguments, and how.
func resultErrorShape(res *mcp.CallToolResult) string {
	if m, ok := res.StructuredContent.(map[string]any); ok {
		if code, ok := structuredExitCode(m[execExitCodeKey]); ok {
			return fmt.Sprintf("exit status %d", code)
		}
	}
	n := 0
	for _, c := range res.Content {
		n += len(c.Text)
	}
	return fmt.Sprintf("the tool reported an error in %d bytes of content", n)
}

// execExitCodeKey is the key sandbox_exec puts a command's exit status under in
// its structured result, and the key resultErrorShape reads it back out of.
// One constant because the two must agree: with the string written out twice,
// renaming it in the tool leaves this reading a key nothing sets, every failed
// command quietly falls through to the byte-count branch, and no test notices
// — a reviewer demonstrated exactly that by renaming it to `exitCode`, at
// which point all three F12 tests still passed.
//
// host/servemcptools.go still writes the literal; TestF12_TheExecResultFixture-
// StillMatchesTheTool checks the two against each other until it uses this.
const execExitCodeKey = "exit_code"

// structuredExitCode reads an exit status out of a result's structured
// content. The value is an `any`: this server builds it as an int, but the
// field is part of a wire-shaped map, so a float — what a JSON round trip
// makes of an integer — is accepted too. Anything else is not an exit status
// and is refused rather than formatted, because %d over an unexpected type is
// how a value nobody sized reaches a record that promises it holds none.
//
// The range is checked as well as the type. A float64 carrying +Inf passes
// math.Trunc unchanged and saturates to 9223372036854775807 on conversion,
// which is not an exit status and would print as one; so would 1e300. Real
// ones run -1 (sandbox.ExecResult's own "no exit code" sentinel) through 255,
// and anything outside that falls through to the byte-count branch rather than
// being reported as a status the guest never returned.
func structuredExitCode(v any) (int, bool) {
	var n int
	switch t := v.(type) {
	case int:
		n = t
	case int64:
		if t < math.MinInt32 || t > math.MaxInt32 {
			return 0, false
		}
		n = int(t)
	case float64:
		if math.IsInf(t, 0) || math.IsNaN(t) || t != math.Trunc(t) {
			return 0, false
		}
		if t < math.MinInt32 || t > math.MaxInt32 {
			return 0, false
		}
		n = int(t)
	default:
		return 0, false
	}
	if n < -1 || n > 255 {
		return 0, false
	}
	return n, true
}

// resultSandbox reads the id out of a structured result, for the tools that
// make a machine rather than being handed one.
func resultSandbox(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	m, ok := res.StructuredContent.(map[string]any)
	if !ok {
		return ""
	}
	if id, ok := m["sandbox"].(string); ok {
		// Clipped like the other writer of this field, so the bound belongs to
		// the field rather than to a reading of every tool. Today every result
		// that reaches here carries an id this server generated — the tools
		// that echo the caller's own string back are the ones that took it as
		// an argument, and those never get this far, because the argument was
		// already recorded — but that is a fact about nine tools, and it would
		// have to be rechecked for the tenth.
		return clipField(id)
	}
	return ""
}

// firstLine is a message's first line, capped. Its one remaining caller is the
// desktop notification of a refusal (E5-7, host/denials.go) — which is read at
// a glance, so the fix line beneath belongs on the terminal where somebody has
// to go to apply it anyway.
//
// It used to summarise a tool result into the audit chain as well. It does not
// any more, and must not again: a notification is shown once to the operator
// who is already watching, while the chain is kept. See resultErrorShape (F12).
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
