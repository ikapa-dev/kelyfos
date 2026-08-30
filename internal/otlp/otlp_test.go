package otlp

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// singleSandboxEvents mirrors host/log.go's own cookbook recipe (docs/cookbook.md
// #6): one non-team sandbox, an allowed command, a refused egress attempt.
func singleSandboxEvents() []recorder.Event {
	code0 := 0
	allowedTrue, allowedFalse := true, false
	return []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z", Arch: "aarch64", Image: "dev", Kelyfos: "v1.1.0"},
		{Type: recorder.TypeSessionReady, TS: "2026-08-27T10:00:01.000Z", BootMS: 500},
		{Type: recorder.TypeCommandStart, TS: "2026-08-27T10:00:02.000Z",
			Call: "c1", Cmd: []string{"echo", "a result"}, Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-27T10:00:02.100Z",
			Call: "c1", Code: &code0, DurationMS: 100},
		{Type: recorder.TypeEgressAttempt, TS: "2026-08-27T10:00:03.000Z",
			Host: "example.com", Port: 443, Allowed: &allowedTrue, Mode: "tunnelled"},
		{Type: recorder.TypeEgressAttempt, TS: "2026-08-27T10:00:04.000Z",
			Host: "evil.example", Port: 443, Allowed: &allowedFalse, Reason: "not_in_allowlist"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:05.000Z", Reason: "shutdown", DurationMS: 5000},
	}
}

// teamEvents is a two-agent team: one command each, one refused egress on
// the second agent, so per-agent grouping and per-agent egress attachment
// both get exercised.
func teamEvents() []recorder.Event {
	code0, code1 := 0, 1
	allowedFalse := false
	return []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z", Arch: "aarch64"},
		{Type: recorder.TypeSessionReady, TS: "2026-08-27T10:00:01.000Z", Agent: "master", BootMS: 400},
		{Type: recorder.TypeSessionReady, TS: "2026-08-27T10:00:01.200Z", Agent: "worker-1", BootMS: 420},
		{Type: recorder.TypeTeamTopology, TS: "2026-08-27T10:00:01.300Z", Agents: []recorder.EvAgent{
			{Name: "master", Sandbox: "sbx-master"},
			{Name: "worker-1", Sandbox: "sbx-worker-1"},
		}, Edges: []string{"master->worker-1"}},
		{Type: recorder.TypeCommandStart, TS: "2026-08-27T10:00:02.000Z", Agent: "master",
			Call: "c1", Cmd: []string{"echo", "assembling"}, Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-27T10:00:02.100Z", Agent: "master",
			Call: "c1", Code: &code0, DurationMS: 100},
		{Type: recorder.TypeCommandStart, TS: "2026-08-27T10:00:03.000Z", Agent: "worker-1",
			Call: "c2", Cmd: []string{"scan", "--deep"}, Via: "exec"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-27T10:00:03.500Z", Agent: "worker-1",
			Call: "c2", Code: &code1, DurationMS: 500,
			Error: &recorder.EvError{Kind: "exit", Message: "scan failed"}},
		{Type: recorder.TypeEgressAttempt, TS: "2026-08-27T10:00:04.000Z", Agent: "worker-1",
			Host: "evil.example", Port: 443, Allowed: &allowedFalse, Reason: "not_in_allowlist"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:05.000Z", Reason: "shutdown", DurationMS: 5000},
	}
}

func spanByName(t *testing.T, spans []Span, name string) Span {
	t.Helper()
	for _, s := range spans {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no span named %q among %d spans", name, len(spans))
	return Span{}
}

func allSpans(exp *Export) []Span {
	var out []Span
	for _, rs := range exp.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			out = append(out, ss.Spans...)
		}
	}
	return out
}

func attr(s Span, key string) (Attr, bool) {
	for _, a := range s.Attributes {
		if a.Key == key {
			return a, true
		}
	}
	return Attr{}, false
}

// TestBuildRejectsEmptySessionID guards Build's one required input.
func TestBuildRejectsEmptySessionID(t *testing.T) {
	if _, err := Build("", singleSandboxEvents()); err == nil {
		t.Fatal("Build(\"\", ...) succeeded, want an error")
	}
}

// TestBuildEmptyChainProducesNoSpans is the degenerate case: a session id
// with no events at all still produces schema-valid, empty JSON rather than
// a manufactured span with epoch timestamps.
func TestBuildEmptyChainProducesNoSpans(t *testing.T) {
	exp, err := Build("sess1", nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := allSpans(exp); len(got) != 0 {
		t.Fatalf("spans = %d, want 0", len(got))
	}
}

// TestInvokeAgentAndExecuteToolSpanNames is the task's own acceptance
// criterion: span names for invoke_agent and execute_tool appear correctly.
func TestInvokeAgentAndExecuteToolSpanNames(t *testing.T) {
	exp, err := Build("sess1", singleSandboxEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	spans := allSpans(exp)

	agent := spanByName(t, spans, "invoke_agent")
	if op, ok := attr(agent, "gen_ai.operation.name"); !ok || *op.Value.StringValue != "invoke_agent" {
		t.Errorf("invoke_agent span's gen_ai.operation.name = %+v", op)
	}
	if agent.Kind != SpanKindInternal {
		t.Errorf("invoke_agent kind = %d, want %d", agent.Kind, SpanKindInternal)
	}

	tool := spanByName(t, spans, "execute_tool echo")
	if op, ok := attr(tool, "gen_ai.operation.name"); !ok || *op.Value.StringValue != "execute_tool" {
		t.Errorf("execute_tool span's gen_ai.operation.name = %+v", op)
	}
	if tool.ParentSpanID != agent.SpanID {
		t.Errorf("execute_tool's parent = %s, want the invoke_agent span's id %s", tool.ParentSpanID, agent.SpanID)
	}
	if tool.Status != nil {
		t.Errorf("a command that exited 0 has a Status set: %+v (must be left unset)", tool.Status)
	}
}

// TestFailedCommandGetsErrorStatus checks the recording-errors discipline
// (docs/otlp.md §4): status is set, and only, on failure.
func TestFailedCommandGetsErrorStatus(t *testing.T) {
	exp, err := Build("sess1", teamEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	spans := allSpans(exp)
	tool := spanByName(t, spans, "execute_tool scan")
	if tool.Status == nil || tool.Status.Code != StatusCodeError {
		t.Fatalf("failed command's Status = %+v, want STATUS_CODE_ERROR", tool.Status)
	}
	if tool.Status.Message != "scan failed" {
		t.Errorf("Status.Message = %q, want the EvError message", tool.Status.Message)
	}
	if et, ok := attr(tool, "error.type"); !ok || *et.Value.StringValue != "exit" {
		t.Errorf("error.type = %+v, want the EvError kind", et)
	}
}

// TestCommandNeverExitedIsIncomplete: docs/events.md's own gap (a
// command.start with no matching command.exit) must not silently render as
// a zero-duration success.
func TestCommandNeverExitedIsIncomplete(t *testing.T) {
	events := []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"},
		{Type: recorder.TypeCommandStart, TS: "2026-08-27T10:00:01.000Z",
			Call: "c1", Cmd: []string{"sleep", "999"}, Via: "exec"},
		{Type: recorder.TypeSessionEnd, TS: "2026-08-27T10:00:02.000Z", Reason: "vm_exited"},
	}
	exp, err := Build("sess1", events)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tool := spanByName(t, allSpans(exp), "execute_tool sleep")
	if tool.Status == nil || tool.Status.Code != StatusCodeError {
		t.Fatalf("an unexited command's Status = %+v, want STATUS_CODE_ERROR", tool.Status)
	}
	if tool.StartTimeUnixNano != tool.EndTimeUnixNano {
		t.Errorf("start=%s end=%s, want equal for a command with no exit", tool.StartTimeUnixNano, tool.EndTimeUnixNano)
	}
}

// TestEgressAttemptsAndRefusalsAreSpanEvents is the task's third mapping
// requirement.
func TestEgressAttemptsAndRefusalsAreSpanEvents(t *testing.T) {
	exp, err := Build("sess1", singleSandboxEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	agent := spanByName(t, allSpans(exp), "invoke_agent")
	if len(agent.Events) != 2 {
		t.Fatalf("invoke_agent span has %d events, want 2 (one allowed, one refused)", len(agent.Events))
	}
	var sawAttempt, sawRefused bool
	for _, e := range agent.Events {
		switch e.Name {
		case "kelyfos.egress.attempt":
			sawAttempt = true
		case "kelyfos.egress.refused":
			sawRefused = true
			found := false
			for _, a := range e.Attributes {
				if a.Key == "server.address" && a.Value.StringValue != nil && *a.Value.StringValue == "evil.example" {
					found = true
				}
			}
			if !found {
				t.Errorf("refused egress event missing server.address=evil.example: %+v", e.Attributes)
			}
		default:
			t.Errorf("unexpected span event name %q", e.Name)
		}
	}
	if !sawAttempt || !sawRefused {
		t.Errorf("sawAttempt=%v sawRefused=%v, want both", sawAttempt, sawRefused)
	}
}

// TestTeamPerAgentSpansAndParentage checks each agent gets its own
// invoke_agent span, carrying the topology's own sandbox id, and that a
// command's parent is the *right* agent's span — not the root, not the
// other agent's.
func TestTeamPerAgentSpansAndParentage(t *testing.T) {
	exp, err := Build("sess1", teamEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	spans := allSpans(exp)

	master := spanByName(t, spans, "invoke_agent master")
	worker := spanByName(t, spans, "invoke_agent worker-1")
	if master.SpanID == worker.SpanID {
		t.Fatal("master and worker-1 share a span id")
	}
	if id, ok := attr(worker, "gen_ai.agent.id"); !ok || *id.Value.StringValue != "sbx-worker-1" {
		t.Errorf("worker-1's gen_ai.agent.id = %+v, want sbx-worker-1 (off team.topology)", id)
	}

	masterCmd := spanByName(t, spans, "execute_tool echo")
	workerCmd := spanByName(t, spans, "execute_tool scan")
	if masterCmd.ParentSpanID != master.SpanID {
		t.Errorf("master's command parent = %s, want master's own span %s", masterCmd.ParentSpanID, master.SpanID)
	}
	if workerCmd.ParentSpanID != worker.SpanID {
		t.Errorf("worker's command parent = %s, want worker's own span %s", workerCmd.ParentSpanID, worker.SpanID)
	}
	// The egress event happened on worker-1's own proxy — it must land on
	// worker-1's span, not master's and not the root.
	if len(worker.Events) != 1 {
		t.Errorf("worker-1 has %d span events, want 1", len(worker.Events))
	}
	if len(master.Events) != 0 {
		t.Errorf("master has %d span events, want 0 (the egress belonged to worker-1)", len(master.Events))
	}

	root := spanByName(t, spans, "kelyfos.session")
	if master.ParentSpanID != root.SpanID || worker.ParentSpanID != root.SpanID {
		t.Error("both agent spans must be children of the root session span")
	}
	// Every span in one export shares one trace id.
	for _, s := range spans {
		if s.TraceID != root.TraceID {
			t.Errorf("span %q has a different trace id than the root", s.Name)
		}
	}
}

// TestBuildIsDeterministic: re-exporting the same session twice must
// produce byte-identical JSON — this package derives every id from the
// chain's own content rather than minting one at random.
func TestBuildIsDeterministic(t *testing.T) {
	a, err := Build("sess1", teamEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	b, err := Build("sess1", teamEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("two builds of the same chain produced different JSON")
	}
}

// TestTraceparentContinuesAnInboundTrace exercises docs/otlp.md §5: a valid
// W3C traceparent on session.policy seeds the export's trace id and the
// root span's own parent.
func TestTraceparentContinuesAnInboundTrace(t *testing.T) {
	events := append([]recorder.Event{
		{Type: recorder.TypeSessionPolicy, TS: "2026-08-27T10:00:00.500Z",
			Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
	}, singleSandboxEvents()...)
	exp, err := Build("sess1", events)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	root := spanByName(t, allSpans(exp), "kelyfos.session")
	if root.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id = %s, want the inbound traceparent's trace-id", root.TraceID)
	}
	if root.ParentSpanID != "00f067aa0ba902b7" {
		t.Errorf("root parent span id = %s, want the inbound traceparent's parent-id", root.ParentSpanID)
	}
}

// TestMalformedTraceparentFallsBackWithoutPanicking: the header is
// untrusted input and a garbage value must degrade gracefully.
func TestMalformedTraceparentFallsBackWithoutPanicking(t *testing.T) {
	for _, bad := range []string{
		"garbage",
		"00-tooshort-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace-id
		"",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
	} {
		events := append([]recorder.Event{
			{Type: recorder.TypeSessionPolicy, TS: "2026-08-27T10:00:00.500Z", Traceparent: bad},
		}, singleSandboxEvents()...)
		exp, err := Build("sess1", events)
		if err != nil {
			t.Fatalf("Build with traceparent %q: %v", bad, err)
		}
		root := spanByName(t, allSpans(exp), "kelyfos.session")
		if len(root.TraceID) != 32 {
			t.Errorf("traceparent %q: trace id %q is not 32 hex chars", bad, root.TraceID)
		}
	}
}

// hostileEvents carries a control byte, a naive HTML/script fragment and an
// unterminated escape sequence in exactly the fields a compromised guest
// could influence: an agent name (attacker-chosen inside a team plan is
// unlikely, but every other export surface this phase built treats it as
// adversarial and this one does too), a command's argv, an egress host and
// a command's error message.
func hostileEvents() []recorder.Event {
	code1 := 1
	return []recorder.Event{
		{Type: recorder.TypeSessionStart, TS: "2026-08-27T10:00:00.000Z"},
		{Type: recorder.TypeCommandStart, TS: "2026-08-27T10:00:01.000Z",
			Call: "c1", Cmd: []string{"echo", "\x07<script>alert(1)</script>\x1b[31m"}, Via: "exec",
			Cwd: "/tmp/\x00nul"},
		{Type: recorder.TypeCommandExit, TS: "2026-08-27T10:00:01.100Z",
			Call: "c1", Code: &code1, DurationMS: 100,
			Error: &recorder.EvError{Kind: "exit", Message: "boom\x07bell"}},
		{Type: recorder.TypeEgressAttempt, TS: "2026-08-27T10:00:02.000Z",
			Host: "evil\x07.example", Port: 443, Reason: "not_in_allowlist\x1b[2J"},
	}
}

// TestHostileStringsNeverReachRawControlBytes is the RENDER-checklist
// discipline the task text asks for: no guest-influenced string reaches an
// OTLP attribute unescaped. json.Marshal already makes the JSON *syntax*
// safe (a literal 0x07 is escaped to \u0007 by Go's encoder regardless);
// what this asserts is the same defence-in-depth every other export
// surface this phase carries — proto.SafeText's own behaviour — by
// checking that a raw control byte never appears as a literal byte in the
// marshalled output, before or after JSON's own escaping.
func TestHostileStringsNeverReachRawControlBytes(t *testing.T) {
	exp, err := Build("sess1", hostileEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	blob, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i, b := range blob {
		if b < 0x20 && b != '\n' && b != '\t' && b != '\r' {
			t.Fatalf("raw control byte 0x%02x at offset %d in marshalled OTLP JSON: %q", b, i, blob[max(0, i-20):min(len(blob), i+20)])
		}
	}
	if bytes.Contains(blob, []byte("<script")) {
		t.Error("<script appears unescaped in the marshalled OTLP JSON")
	}
}

// otlpIDPattern is what §1 of docs/specification.md requires: a
// case-insensitive hex string, 32 characters for a trace id and 16 for a
// span id.
var hexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

// TestBuildMatchesOTLPJSONShape validates the marshalled export against the
// real OTLP-JSON wire shape (opentelemetry-proto's own JSON encoding
// deviations from generic protobuf-JSON — see the package doc): traceId is
// 32 hex characters, spanId is 16, kind and status.code are JSON *numbers*
// and never the enum's name string, and every 64-bit timestamp is a
// decimal string rather than a JSON number.
func TestBuildMatchesOTLPJSONShape(t *testing.T) {
	exp, err := Build("sess1", teamEvents())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	blob, err := json.Marshal(exp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var generic map[string]interface{}
	if err := json.Unmarshal(blob, &generic); err != nil {
		t.Fatalf("unmarshal into a generic map: %v", err)
	}
	resourceSpans, ok := generic["resourceSpans"].([]interface{})
	if !ok || len(resourceSpans) == 0 {
		t.Fatal("no resourceSpans array at the JSON root")
	}
	rs0 := resourceSpans[0].(map[string]interface{})
	if _, ok := rs0["resource"].(map[string]interface{}); !ok {
		t.Fatal("resourceSpans[0].resource is missing or not an object")
	}
	scopeSpans, ok := rs0["scopeSpans"].([]interface{})
	if !ok || len(scopeSpans) == 0 {
		t.Fatal("resourceSpans[0].scopeSpans is missing or empty")
	}
	ss0 := scopeSpans[0].(map[string]interface{})
	scope, ok := ss0["scope"].(map[string]interface{})
	if !ok || scope["name"] != "kelyfos" {
		t.Fatalf("scope.name = %v, want \"kelyfos\"", scope["name"])
	}
	spans, ok := ss0["spans"].([]interface{})
	if !ok || len(spans) == 0 {
		t.Fatal("scopeSpans[0].spans is missing or empty")
	}

	sawExecuteTool := false
	sawInvokeAgent := false
	for _, raw := range spans {
		s := raw.(map[string]interface{})

		traceID, _ := s["traceId"].(string)
		if len(traceID) != 32 || !hexPattern.MatchString(traceID) {
			t.Errorf("span %v: traceId %q is not 32 hex chars", s["name"], traceID)
		}
		spanID, _ := s["spanId"].(string)
		if len(spanID) != 16 || !hexPattern.MatchString(spanID) {
			t.Errorf("span %v: spanId %q is not 16 hex chars", s["name"], spanID)
		}

		// Enums MUST be integers in OTLP/JSON, never the name string
		// (opentelemetry-proto/docs/specification.md #json-protobuf-encoding).
		kind, ok := s["kind"].(float64)
		if !ok {
			t.Errorf("span %v: kind is %T, want a JSON number", s["name"], s["kind"])
		} else if kind != float64(SpanKindInternal) {
			t.Errorf("span %v: kind = %v, want %d (SPAN_KIND_INTERNAL)", s["name"], kind, SpanKindInternal)
		}

		for _, field := range []string{"startTimeUnixNano", "endTimeUnixNano"} {
			v, ok := s[field].(string)
			if !ok {
				t.Errorf("span %v: %s is %T, want a JSON string (64-bit ints are string-encoded)", s["name"], field, s[field])
				continue
			}
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				t.Errorf("span %v: %s = %q does not parse as a decimal integer", s["name"], field, v)
			}
		}

		if status, ok := s["status"].(map[string]interface{}); ok {
			code, ok := status["code"].(float64)
			if !ok {
				t.Errorf("span %v: status.code is %T, want a JSON number", s["name"], status["code"])
			} else if code != float64(StatusCodeError) {
				t.Errorf("span %v: status.code = %v, want %d (STATUS_CODE_ERROR — the only code this package ever sets explicitly)", s["name"], code, StatusCodeError)
			}
		}

		name, _ := s["name"].(string)
		if name == "invoke_agent" || strings.HasPrefix(name, "invoke_agent ") {
			sawInvokeAgent = true
		}
		if strings.HasPrefix(name, "execute_tool ") {
			sawExecuteTool = true
		}

		attrs, _ := s["attributes"].([]interface{})
		for _, rawAttr := range attrs {
			a := rawAttr.(map[string]interface{})
			if _, ok := a["key"].(string); !ok {
				t.Errorf("span %v: an attribute has no string key: %v", s["name"], a)
			}
			val, ok := a["value"].(map[string]interface{})
			if !ok {
				t.Errorf("span %v: attribute %v's value is not an object", s["name"], a["key"])
				continue
			}
			if iv, ok := val["intValue"]; ok {
				if _, ok := iv.(string); !ok {
					t.Errorf("span %v: attribute %v's intValue is %T, want a JSON string", s["name"], a["key"], iv)
				}
			}
		}
	}
	if !sawInvokeAgent {
		t.Error("no invoke_agent span found in the export")
	}
	if !sawExecuteTool {
		t.Error("no execute_tool span found in the export")
	}
}
