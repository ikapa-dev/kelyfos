// Package otlp maps one session's flight recorder chain onto an OTLP-JSON
// trace export (P7-11), for `kelyfos log --export-otlp`.
//
// This is a one-way, lossy projection for interoperability with existing
// observability tooling — it is never read back, and internal/recorder's
// Event struct and its frozen field order are never touched by anything in
// this package (D59). As of the v1.42 OpenTelemetry GenAI semantic
// conventions, every gen_ai.* attribute this package writes still carries
// the "Development" stability badge with no stabilisation timeline, so this
// mapping is versioned apart from the chain and is never an input to
// `kelyfos verify`: a future revision of the GenAI conventions can change
// this package freely without touching a single hashed byte. See
// docs/otlp.md for the full field-by-field mapping and what is deliberately
// left out.
//
// The wire shapes below (Export, ResourceSpans, Span, ...) are a minimal,
// hand-written subset of opentelemetry-proto's trace_service.proto,
// following its own JSON encoding rules exactly rather than the generic
// protobuf-JSON mapping — the two differ in three ways that matter here,
// confirmed against opentelemetry-proto/docs/specification.md
// (#json-protobuf-encoding) rather than assumed: trace/span IDs are
// case-insensitive hex strings, not base64; enum fields (Kind, Status.Code)
// are encoded as their integer values, never as name strings; and every
// 64-bit integer (the two timestamps) is a decimal string. Getting any of
// the three wrong produces JSON that looks right and is not — exactly the
// kind of drift TestBuildMatchesOTLPJSONShape exists to catch.
package otlp

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// SpanKind values, encoded as integers per OTLP/JSON (never as the enum's
// name string — see the package doc).
const (
	SpanKindInternal = 1
)

// StatusCode values, encoded as integers per OTLP/JSON. StatusCodeUnset is
// the default and is never written explicitly: per
// docs/general/recording-errors.md, "Span Status Code MUST be left unset if
// the instrumented operation has ended without any errors," so Span.Status
// is nil unless something actually went wrong.
const (
	StatusCodeError = 2
)

// Export is the JSON shape of an OTLP ExportTraceServiceRequest — the root
// object `kelyfos log --export-otlp` writes.
type Export struct {
	ResourceSpans []ResourceSpans `json:"resourceSpans"`
}

type ResourceSpans struct {
	Resource   Resource     `json:"resource"`
	ScopeSpans []ScopeSpans `json:"scopeSpans"`
}

type Resource struct {
	Attributes []Attr `json:"attributes,omitempty"`
}

type ScopeSpans struct {
	Scope Scope  `json:"scope"`
	Spans []Span `json:"spans"`
}

type Scope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Span is one OTLP span. Kind and Status.Code are Go ints, marshalled as
// JSON numbers — OTLP/JSON's own deviation from generic protobuf-JSON
// enum encoding (package doc). StartTimeUnixNano/EndTimeUnixNano are
// strings because every 64-bit integer in OTLP/JSON is a decimal string.
type Span struct {
	TraceID           string  `json:"traceId"`
	SpanID            string  `json:"spanId"`
	ParentSpanID      string  `json:"parentSpanId,omitempty"`
	Name              string  `json:"name"`
	Kind              int     `json:"kind"`
	StartTimeUnixNano string  `json:"startTimeUnixNano"`
	EndTimeUnixNano   string  `json:"endTimeUnixNano"`
	Attributes        []Attr  `json:"attributes,omitempty"`
	Events            []Event `json:"events,omitempty"`
	Status            *Status `json:"status,omitempty"`
}

// Event is an OTLP span event — how egress attempts and refusals ride on an
// invoke_agent span (docs/otlp.md §3).
type Event struct {
	TimeUnixNano string `json:"timeUnixNano"`
	Name         string `json:"name"`
	Attributes   []Attr `json:"attributes,omitempty"`
}

// Status is set only when Span.Status is non-nil, i.e. only on an error —
// see StatusCodeError's own doc comment.
type Status struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// Attr is one OTLP KeyValue.
type Attr struct {
	Key   string `json:"key"`
	Value Value  `json:"value"`
}

// Value is OTLP's AnyValue, restricted to the three kinds this package ever
// writes.
type Value struct {
	StringValue *string `json:"stringValue,omitempty"`
	BoolValue   *bool   `json:"boolValue,omitempty"`
	// IntValue is a string, like the span timestamps: every 64-bit integer
	// in OTLP/JSON is decimal-string encoded (package doc).
	IntValue *string `json:"intValue,omitempty"`
}

func strAttr(key, val string) Attr       { return Attr{Key: key, Value: Value{StringValue: &val}} }
func boolAttr(key string, val bool) Attr { return Attr{Key: key, Value: Value{BoolValue: &val}} }
func intAttr(key string, val int64) Attr {
	s := strconv.FormatInt(val, 10)
	return Attr{Key: key, Value: Value{IntValue: &s}}
}

// safe is proto.SafeText, reused rather than duplicated — the same
// RENDER-checklist discipline internal/report/safe.go applies to every
// guest-influenced value this package writes into an OTLP attribute or
// span/event name: an agent name, a command's argv, a path, an egress
// host, an error message. json.Marshal already makes the *syntax* safe;
// this is the same defence-in-depth pass every other export surface this
// phase has built already carries, for a raw control byte or terminal
// escape sequence a downstream tool might render unsafely.
func safe(s string) string { return proto.SafeText(s) }

// tsLayout is recorder.Append's own timestamp format (recorder.go), parsed
// back out rather than reformatted from scratch so a change to one place
// cannot silently disagree with the other.
const tsLayout = "2006-01-02T15:04:05.000Z07:00"

func parseTS(s string) (time.Time, bool) {
	t, err := time.Parse(tsLayout, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func nanoStr(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UnixNano(), 10)
}

// idBytes derives n deterministic bytes from a sequence of parts, joined by
// a NUL separator so "a","bc" and "ab","c" cannot collide. Deterministic
// rather than crypto/rand-minted: re-exporting the same session twice must
// produce byte-identical output (TestBuildIsDeterministic), the same way
// internal/graph's own layout is deterministic by construction.
func idBytes(n int, parts ...string) []byte {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte{0})
		}
		h.Write([]byte(p))
	}
	return h.Sum(nil)[:n]
}

func traceIDHex(parts ...string) string { return fmt.Sprintf("%x", idBytes(16, parts...)) }
func spanIDHex(parts ...string) string  { return fmt.Sprintf("%x", idBytes(8, parts...)) }

// isHex reports whether every byte of s is a hex digit — used only to
// validate an inbound, untrusted traceparent header before touching it.
func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	for _, r := range s {
		if r != '0' {
			return false
		}
	}
	return true
}

// parseTraceparent is a minimal, defensive parser for the W3C traceparent
// header (https://www.w3.org/TR/trace-context/#traceparent-header):
// "{2-hex version}-{32-hex trace-id}-{16-hex parent-id}-{2-hex flags}". The
// value on session.policy (docs/policy-record.md §8.7) is stored opaque and
// unvalidated — exactly the case that document flagged as "a P7-11 concern
// if it turns out to be one." It has: an inbound trace lets this session's
// own OTLP export continue the caller's trace instead of starting a new
// one. The header is untrusted (an operator or a parent session supplied
// it, not this session's own guest, but it is still parsed defensively) —
// a malformed value yields ok=false rather than a panic.
func parseTraceparent(tp string) (traceID, parentID string, ok bool) {
	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		return "", "", false
	}
	version, trace, parent, flags := parts[0], parts[1], parts[2], parts[3]
	if len(version) != 2 || len(trace) != 32 || len(parent) != 16 || len(flags) != 2 {
		return "", "", false
	}
	if !isHex(version) || !isHex(trace) || !isHex(parent) || !isHex(flags) {
		return "", "", false
	}
	if allZero(trace) || allZero(parent) {
		return "", "", false
	}
	return strings.ToLower(trace), strings.ToLower(parent), true
}

// timeRange tracks the earliest and latest timestamp seen for one span, so
// its start/end can be derived from what the chain actually observed
// instead of assumed.
type timeRange struct {
	start, end time.Time
	has        bool
}

func (r *timeRange) extend(t time.Time) {
	if t.IsZero() {
		return
	}
	if !r.has || t.Before(r.start) {
		r.start = t
	}
	if !r.has || t.After(r.end) {
		r.end = t
	}
	r.has = true
}

// Build maps one session's chain to an OTLP-JSON trace export: one
// invoke_agent span per agent (or exactly one, for the implicit single
// agent of a non-team session), one execute_tool span per command, and
// every egress attempt or refusal as a span event on the agent it belongs
// to (docs/otlp.md §2-3).
//
// events is read, never written — this derives everything it needs from
// what internal/digest already folds out of the chain, the same fold
// kelyfos watch and the exported HTML report both build on, rather than
// re-deriving its own second reading of the raw events (P7-1's own reason
// for existing).
func Build(sessionID string, events []recorder.Event) (*Export, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("otlp: session id is required")
	}

	d := digest.Walk(events)

	// An empty slice rather than nil so the JSON is "spans":[] and not
	// "spans":null — both are valid OTLP/JSON, but a reader should not have
	// to special-case an empty chain's export against every other one.
	spans := []Span{}
	if len(events) > 0 {
		spans = buildSpans(sessionID, d)
	}

	return &Export{
		ResourceSpans: []ResourceSpans{{
			Resource: Resource{Attributes: resourceAttrs(sessionID, d)},
			ScopeSpans: []ScopeSpans{{
				Scope: Scope{Name: "kelyfos", Version: d.Kelyfos},
				Spans: spans,
			}},
		}},
	}, nil
}

// resourceAttrs identifies the producing process — what every span in this
// export was recorded by — as distinct from the session's own facts
// (rootSpanAttrs), the usual OTLP split between "who is reporting" and
// "what happened."
func resourceAttrs(sessionID string, d *digest.Digest) []Attr {
	attrs := []Attr{
		strAttr("service.name", "kelyfos"),
		strAttr("kelyfos.session.id", sessionID),
	}
	if d.Kelyfos != "" {
		attrs = append(attrs, strAttr("service.version", d.Kelyfos))
	}
	return attrs
}

func rootSpanAttrs(d *digest.Digest) []Attr {
	var attrs []Attr
	if d.Arch != "" {
		attrs = append(attrs, strAttr("kelyfos.arch", d.Arch))
	}
	if d.Image != "" {
		attrs = append(attrs, strAttr("kelyfos.image", safe(d.Image)))
	}
	attrs = append(attrs, boolAttr("kelyfos.team", d.Team))
	attrs = append(attrs, boolAttr("kelyfos.served", d.Served))
	if d.EndReason != "" {
		attrs = append(attrs, strAttr("kelyfos.session.end_reason", safe(d.EndReason)))
	}
	return attrs
}

// deriveTraceID looks for an inbound W3C traceparent on the session's own
// session.policy (the agentless one outside a team; the first agent that
// carries one, in boot order, inside a team — a team's shared trace is one
// export regardless of which member's own door received the header) and
// continues that trace when one parses. Otherwise every span in this
// export shares a trace id derived deterministically from the session id.
func deriveTraceID(sessionID string, d *digest.Digest) (traceID, rootParentSpanID string) {
	tp := ""
	if d.Policy != nil {
		tp = d.Policy.Traceparent
	} else {
		for _, name := range d.AgentOrder {
			if a := d.Agents[name]; a != nil && a.Policy != nil && a.Policy.Traceparent != "" {
				tp = a.Policy.Traceparent
				break
			}
		}
	}
	if tp != "" {
		if tid, pid, ok := parseTraceparent(tp); ok {
			return tid, pid
		}
	}
	return traceIDHex("trace", sessionID), ""
}

// agentGroups is every span this export gives its own invoke_agent span:
// one per named team member, in boot order, or the single implicit agent
// (named "") a non-team session's chain still has — "agents (implicitly,
// one)," in the task's own words.
func agentGroups(d *digest.Digest) []string {
	if !d.Team {
		return []string{""}
	}
	return append([]string(nil), d.AgentOrder...)
}

func agentSpanName(name string) string {
	if name == "" {
		return "invoke_agent"
	}
	return "invoke_agent " + safe(name)
}

func agentAttrs(name, sandboxID string) []Attr {
	attrs := []Attr{strAttr("gen_ai.operation.name", "invoke_agent")}
	if name != "" {
		attrs = append(attrs, strAttr("gen_ai.agent.name", safe(name)))
	}
	if sandboxID != "" {
		attrs = append(attrs, strAttr("gen_ai.agent.id", safe(sandboxID)))
	}
	return attrs
}

func buildSpans(sessionID string, d *digest.Digest) []Span {
	traceID, inboundParent := deriveTraceID(sessionID, d)
	rootID := spanIDHex("session", sessionID)

	sandboxByAgent := map[string]string{}
	if d.Topology != nil {
		for _, a := range d.Topology.Agents {
			sandboxByAgent[a.Name] = a.Sandbox
		}
	}

	groups := agentGroups(d)
	agentSpanID := make(map[string]string, len(groups))
	ranges := make(map[string]*timeRange, len(groups))
	agentEvents := make(map[string][]Event, len(groups))
	for _, name := range groups {
		agentSpanID[name] = spanIDHex("agent", sessionID, name)
		ranges[name] = &timeRange{}
	}

	root := &timeRange{}
	isTeam := d.Team
	var commandSpans []Span

	for _, entry := range d.Timeline {
		ts, tsOK := parseTS(entry.TS)
		if tsOK {
			root.extend(ts)
		}
		group := entry.Agent
		if !isTeam {
			group = ""
		}
		if r, ok := ranges[group]; ok && tsOK {
			r.extend(ts)
		}

		switch entry.Category {
		case "command":
			if _, ok := agentSpanID[group]; !ok {
				continue
			}
			span, endTS := buildCommandSpan(sessionID, traceID, agentSpanID[group], entry)
			commandSpans = append(commandSpans, span)
			if r, ok := ranges[group]; ok {
				r.extend(endTS)
			}
			root.extend(endTS)
		case "egress":
			if _, ok := agentSpanID[group]; ok {
				agentEvents[group] = append(agentEvents[group], buildEgressEvent(entry))
			}
		}
	}

	spans := make([]Span, 0, 1+len(groups)+len(commandSpans))

	rootSpan := Span{
		TraceID:           traceID,
		SpanID:            rootID,
		ParentSpanID:      inboundParent,
		Name:              "kelyfos.session",
		Kind:              SpanKindInternal,
		StartTimeUnixNano: nanoStr(root.start),
		EndTimeUnixNano:   nanoStr(root.end),
		Attributes:        rootSpanAttrs(d),
	}
	if d.EndReason == "error" || d.EndReason == "timeout" {
		rootSpan.Status = &Status{Code: StatusCodeError, Message: safe(d.EndReason)}
		rootSpan.Attributes = append(rootSpan.Attributes, strAttr("error.type", d.EndReason))
	}
	spans = append(spans, rootSpan)

	for _, name := range groups {
		r := ranges[name]
		start, end := r.start, r.end
		if !r.has {
			start, end = root.start, root.end
		}
		spans = append(spans, Span{
			TraceID:           traceID,
			SpanID:            agentSpanID[name],
			ParentSpanID:      rootID,
			Name:              agentSpanName(name),
			Kind:              SpanKindInternal,
			StartTimeUnixNano: nanoStr(start),
			EndTimeUnixNano:   nanoStr(end),
			Attributes:        agentAttrs(name, sandboxByAgent[name]),
			Events:            agentEvents[name],
		})
	}

	spans = append(spans, commandSpans...)
	return spans
}

// buildCommandSpan maps one command.start entry (already folded together
// with its command.exit by internal/digest) to an execute_tool span.
func buildCommandSpan(sessionID, traceID, parentID string, entry *digest.Entry) (Span, time.Time) {
	toolName := "shell"
	if len(entry.Cmd) > 0 && entry.Cmd[0] != "" {
		toolName = entry.Cmd[0]
	}
	safeTool := safe(toolName)

	startTS, _ := parseTS(entry.TS)
	endTS := startTS
	if entry.Exited {
		endTS = startTS.Add(time.Duration(entry.DurationMS) * time.Millisecond)
	}

	// entry.Seq (from the embedded recorder.Event) is folded into the span
	// id alongside Call: Call is meant to be unique per command, but a
	// malformed or adversarial chain is exactly the input this must not
	// collide on, and Seq (the chain's own line number) always is.
	id := spanIDHex("cmd", sessionID, entry.Call, strconv.Itoa(entry.Seq))

	attrs := []Attr{
		strAttr("gen_ai.operation.name", "execute_tool"),
		strAttr("gen_ai.tool.name", safeTool),
	}
	if entry.Call != "" {
		attrs = append(attrs, strAttr("gen_ai.tool.call.id", safe(entry.Call)))
	}
	if entry.Agent != "" {
		attrs = append(attrs, strAttr("gen_ai.agent.name", safe(entry.Agent)))
	}
	if len(entry.Cmd) > 0 {
		attrs = append(attrs, strAttr("kelyfos.command.argv", safe(strings.Join(entry.Cmd, " "))))
	}
	if entry.Cwd != "" {
		attrs = append(attrs, strAttr("kelyfos.command.cwd", safe(entry.Cwd)))
	}
	if entry.Via != "" {
		attrs = append(attrs, strAttr("kelyfos.command.via", safe(entry.Via)))
	}
	if entry.Code != nil {
		attrs = append(attrs, intAttr("kelyfos.command.exit_code", int64(*entry.Code)))
	}
	attrs = append(attrs, boolAttr("kelyfos.command.exited", entry.Exited))

	span := Span{
		TraceID:           traceID,
		SpanID:            id,
		ParentSpanID:      parentID,
		Name:              "execute_tool " + safeTool,
		Kind:              SpanKindInternal,
		StartTimeUnixNano: nanoStr(startTS),
		EndTimeUnixNano:   nanoStr(endTS),
		Attributes:        attrs,
	}

	// docs/general/recording-errors.md: status MUST be left unset when the
	// operation ended without error, and error.type/status.message are set
	// only when it did not.
	switch {
	case !entry.Exited:
		span.Status = &Status{Code: StatusCodeError, Message: "did not exit before the chain ended"}
		span.Attributes = append(span.Attributes, strAttr("error.type", "incomplete"))
	case entry.Code != nil && *entry.Code != 0:
		errType := fmt.Sprintf("exit_%d", *entry.Code)
		msg := errType
		if entry.Error != nil {
			if entry.Error.Kind != "" {
				errType = entry.Error.Kind
			}
			if entry.Error.Message != "" {
				msg = safe(entry.Error.Message)
			}
		}
		span.Status = &Status{Code: StatusCodeError, Message: msg}
		span.Attributes = append(span.Attributes, strAttr("error.type", safe(errType)))
	}

	return span, endTS
}

// buildEgressEvent maps one egress.attempt entry to a span event on the
// agent it belongs to. server.address/server.port are the stable, generic
// OTel network attributes (not gen_ai.*), reused rather than inventing a
// kelyfos-specific pair for the same two facts.
func buildEgressEvent(entry *digest.Entry) Event {
	ts, _ := parseTS(entry.TS)
	allowed := entry.Allowed != nil && *entry.Allowed
	name := "kelyfos.egress.attempt"
	if !allowed {
		name = "kelyfos.egress.refused"
	}
	attrs := []Attr{boolAttr("kelyfos.egress.allowed", allowed)}
	if entry.Host != "" {
		attrs = append(attrs, strAttr("server.address", safe(entry.Host)))
	}
	if entry.Port != 0 {
		attrs = append(attrs, intAttr("server.port", int64(entry.Port)))
	}
	if entry.Mode != "" {
		attrs = append(attrs, strAttr("kelyfos.egress.mode", safe(entry.Mode)))
	}
	if entry.Reason != "" {
		attrs = append(attrs, strAttr("kelyfos.egress.reason", safe(entry.Reason)))
	}
	if entry.BytesIn > 0 {
		attrs = append(attrs, intAttr("kelyfos.egress.bytes_in", entry.BytesIn))
	}
	if entry.BytesOut > 0 {
		attrs = append(attrs, intAttr("kelyfos.egress.bytes_out", entry.BytesOut))
	}
	return Event{TimeUnixNano: nanoStr(ts), Name: name, Attributes: attrs}
}
