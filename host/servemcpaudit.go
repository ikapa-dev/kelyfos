package main

import (
	"encoding/json"
	"fmt"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"sort"
	"strings"
	"time"

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

// contentKeys are the arguments a record must never hold, because they carry
// content rather than intent. The rule is the one file.write already follows:
// what was written is recorded by size and digest, never by value.
//
// `data` is here because the guest's `upload` carries base64 file contents under
// that name and the guest-side summariser (supervisor/pluginhost.go) has always
// redacted it. This list did not, so the two were not the same shape even though
// docs/mcp-surface.md said they were — and the summariser's own promise, that an
// argument carrying content is replaced "including on a tool that does not exist
// yet", was only true for two of the three names.
var contentKeys = map[string]bool{"content": true, "stdin": true, "data": true}

// summariseArgs renders a call's arguments for the record.
//
// It walks whatever it was given rather than knowing the tools, so an argument
// added later is visible in the log without anyone remembering to add it here —
// and an argument that carries content is replaced by its size wherever it
// appears, including on a tool that does not exist yet.
func summariseArgs(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		// Unparseable arguments are a fact about the call, and the call is
		// still recorded: a client sending malformed JSON is exactly the kind
		// of thing a transcript should show.
		return fmt.Sprintf("<unparseable, %d bytes>", len(raw))
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		v := m[k]
		if contentKeys[k] {
			if str, ok := v.(string); ok {
				parts = append(parts, fmt.Sprintf("%s=<%d bytes>", k, len(str)))
				continue
			}
		}
		parts = append(parts, proto.SafeText(k)+"="+compactValue(v))
	}
	return strings.Join(parts, " ")
}

// compactValue renders one argument. Long strings are truncated with their full
// length named, so a log line stays a line and still says what it was cut from.
func compactValue(v any) string {
	switch t := v.(type) {
	case string:
		if len(t) > 120 {
			return fmt.Sprintf("%q…(%d bytes)", t[:120], len(t))
		}
		return proto.SafeText(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, compactValue(e))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	default:
		blob, err := json.Marshal(v)
		if err != nil {
			return "?"
		}
		return string(blob)
	}
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
	return a.Sandbox
}

// openAudit gives the server its own session. A serve-mcp process is a session
// in the same sense a `kelyfos run` is: it starts, it does things, it ends, and
// the record of it outlives it.
func (s *hostServer) openAudit() error {
	id, err := sandbox.NewID()
	if err != nil {
		return err
	}
	rec, err := recorder.Open(sandbox.Root(), id)
	if err != nil {
		return err
	}
	s.auditID, s.audit = id, rec
	return rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Arch: s.arch, Kelyfos: Version,
		Argv: s.argv, Reason: recorder.ReasonServeMCP,
	})
}

func (s *hostServer) closeAudit() {
	if s.audit == nil {
		return
	}
	_ = s.audit.Append(recorder.Event{
		Type: recorder.TypeSessionEnd, Reason: "shutdown",
		DurationMS: s.audit.Since().Milliseconds(),
	})
	_ = s.audit.Close()
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
	_ = s.audit.Append(recorder.Event{
		Type: recorder.TypeMCPHostCall, Call: call, Name: p.Name,
		Agent: box, Args: summariseArgs(p.Arguments),
	})
	started := time.Now()
	return func(res *mcp.CallToolResult) {
		ev := recorder.Event{
			Type: recorder.TypeMCPHostResult, Call: call, Name: p.Name,
			Agent: box, Outcome: "ok", DurationMS: time.Since(started).Milliseconds(),
		}
		// A call that created a sandbox names it only in its answer, and that
		// is the one call whose lane matters most.
		if ev.Agent == "" {
			ev.Agent = resultSandbox(res)
		}
		if res != nil && res.IsError {
			ev.Outcome = "error"
			msg := ""
			if len(res.Content) > 0 {
				msg = firstLine(res.Content[0].Text)
			}
			ev.Error = &recorder.EvError{Kind: "tool", Message: msg}
		}
		_ = s.audit.Append(ev)
	}
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
		return id
	}
	return ""
}

// firstLine is a message's first line, capped. Used for the audit summary of a
// tool result, and for a desktop notification of a refusal (E5-7) — which is
// read at a glance, so the fix line beneath belongs on the terminal where
// somebody has to go to apply it anyway.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
