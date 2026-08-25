package main

import (
	"encoding/json"
	"fmt"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

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

// The bounds that keep a record line readable.
//
// Nothing upstream of this file bounds what a client puts in a tool call. serve
// reads a frame of up to proto.MaxMCPLine — 16 MiB (host/servemcp.go) — and
// callTool audits before it dispatches, so a call naming a tool this server does
// not have is summarised and written exactly like a real one. Every reader of
// the chain is smaller than that writer: recorder.Verify, recorder.Read and
// `kelyfos log`'s replay each read a line with a bufio.Scanner capped at 8 MiB,
// and recorder.Append has no size guard of its own — it writes what it is
// given. One call carrying nine megabytes under any key therefore wrote a line
// none of the three can read again, and because the chain is a chain, every
// line after it goes with it: `kelyfos verify` stops at the scanner error and
// the record is unreadable from there on. That is durable, it survives the
// process, and the caller chose it.
//
// Which is why the bound cannot be only on the keys that carry content, or only
// on the branch that marshals an object. It has to be on the line: nothing
// limits how many keys an object has or how long one of them is, so a summary
// of a thousand short arguments passes every per-argument cap and is still
// megabytes.
//
// Neither number changes what a real call renders. 120 bytes is the cap the
// string branch has always applied, and no tool declares an object-valued or
// deeply nested argument — every property of every InputSchema in
// host/servemcptools.go, host/servemcpteam.go, supervisor/tools.go and
// supervisor/teamtools.go is a string, an integer or an array of strings. 4 KiB
// is far above anything a legitimate call renders and three orders of magnitude
// below the smallest reader's line cap.
const (
	maxArgBytes  = 120
	maxArgsBytes = 4 << 10
	// An array's whole rendering, which is deliberately far above maxArgBytes:
	// the egress allowlist arrives as an array and is recorded nowhere else, so
	// cutting it short loses the only note of what an agent asked to reach.
	// maxArgsBytes still bounds the joined line however this is spent.
	maxArrayBytes = 1 << 10
)

// summariseArgs renders a call's arguments for the record.
//
// It walks whatever it was given rather than knowing the tools, so an argument
// added later is visible in the log without anyone remembering to add it here —
// and an argument that carries content is replaced by its size on whatever tool
// it appears on, including a tool that does not exist yet.
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
			parts = append(parts, k+"="+contentSize(v))
			continue
		}
		parts = append(parts, proto.SafeText(k)+"="+compactValue(v))
	}
	out := strings.Join(parts, " ")
	if len(out) > maxArgsBytes {
		// The last bound, and the one that holds however the caller shaped the
		// call: a key is as unbounded as a value, and an object may have as
		// many of them as fit in the frame.
		return fmt.Sprintf("%s…(%d bytes)", clipUTF8(out, maxArgsBytes), len(out))
	}
	return out
}

// clipUTF8 cuts s to at most n bytes without leaving half a rune at the end.
//
// A summary is marshalled into the record and printed to a terminal. A trailing
// fragment of a multi-byte character is neither: json.Marshal would replace it
// with U+FFFD in the line that gets hashed, and the terminal would show
// something else again. Dropping the fragment costs at most three bytes of a
// summary that has already said how long the whole thing was.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 {
		// DecodeLastRuneInString reports (RuneError, 1) for a broken tail and
		// (U+FFFD, 3) for a replacement character that is genuinely there, so a
		// character the JSON decoder already substituted is kept.
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

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

// contentSize is what an argument carrying content is replaced by: its size,
// and never its value.
//
// The rule is about the key and not about the type the caller chose to put
// under it. A string is measured as itself; anything else — an object, an
// array, a number — is measured as the JSON it arrived as. Recognising only a
// string here would have left the redaction guarantee decided by the caller,
// who picks the shape as well as the bytes: the same content wrapped in an
// object fell through to compactValue, whose last resort was json.Marshal with
// no length to stop at, and was written into the record whole under the one key
// this code promises never to hold by value. That last resort is bounded now
// too, but a bounded rendering of content is still content: the key is what
// decides, and under these three names nothing is rendered at all.
func contentSize(v any) string {
	if s, ok := v.(string); ok {
		return fmt.Sprintf("<%d bytes>", len(s))
	}
	blob, err := json.Marshal(v)
	if err != nil {
		// A value that came out of json.Unmarshal marshals again, so there is
		// no known way here. If one is ever found, the half of the promise
		// worth keeping is the half that withholds.
		return "<withheld>"
	}
	return fmt.Sprintf("<%d bytes>", len(blob))
}

// compactValue renders one argument. Long values are truncated with their full
// length named, so a log line stays a line and still says what it was cut from.
//
// Every branch is bounded, not only the string one. The cap here was the string
// branch's alone, which left an argument's size decided by the type the caller
// chose to send: the same bytes inside an object went to the default branch and
// were marshalled whole, and the same bytes spread across an array were
// rendered element by element with nothing counting them.
func compactValue(v any) string {
	switch t := v.(type) {
	case string:
		if len(t) > maxArgBytes {
			return fmt.Sprintf("%q…(%d bytes)", t[:maxArgBytes], len(t))
		}
		return proto.SafeText(t)
	case []any:
		parts := make([]string, 0, len(t))
		used := 0
		for i, e := range t {
			// The budget is generous rather than tight, because the thing most
			// often carried in an array here is the egress allowlist — and that
			// is recorded nowhere else. recorder.Event has no allowlist field
			// and session.start does not carry one, so this string is the only
			// record of which domains an agent asked its sandbox to reach. A
			// 120-byte budget spent across the whole array cut a real
			// eight-domain list short, which is audit fidelity lost on ordinary
			// traffic to bound a case the 4 KiB clip on the joined line already
			// bounds (P6-28). Checked before the element rather than after it,
			// so an array always renders at least its first.
			if used >= maxArrayBytes {
				parts = append(parts, fmt.Sprintf("…(%d more)", len(t)-i))
				break
			}
			s := compactValue(e)
			used += len(s) + 1
			parts = append(parts, s)
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
		if len(blob) > maxArgBytes {
			// In practice an object: a bool renders in five bytes and a null in
			// four, and nothing else reaches here. Quoted rather than cut raw,
			// because %q escapes a rune the cut ran through as well as anything
			// the marshalled JSON left unescaped.
			return fmt.Sprintf("%q…(%d bytes)", blob[:maxArgBytes], len(blob))
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
	// Bounded here rather than at the two places the id is written, because
	// recording an id this server has never heard of is the point of the lane
	// and the caller picks the bytes.
	return clipField(a.Sandbox)
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
