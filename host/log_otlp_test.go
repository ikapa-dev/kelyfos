package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// chainOf writes these events through the real, hash-chained recorder and
// hands back the path `kelyfos log --export-otlp` would be pointed at —
// internal/report/report_test.go's own chainOf, adapted to hand back a path
// (exportOTLPSession's own signature) rather than a blob. A real recorder
// file rather than hand-marshalled JSON lines, for the same reason that
// file gives: this is a RENDER surface, and what every assertion below
// rests on is that the file the CLI's export command reads is the file the
// flight recorder actually wrote, seq/prev/hash and all.
func chainOf(t *testing.T, events []recorder.Event) (root, sessionID, path string) {
	t.Helper()
	root = t.TempDir()
	sessionID = "s1"
	rec, err := recorder.Open(root, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := rec.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return root, sessionID, recorder.Path(root, sessionID)
}

var otlpHexID = regexp.MustCompile(`^[0-9a-f]+$`)

// TestExportOTLPValidatesAgainstTheRealOTLPJSONShape is P7-11's own "real
// verification" requirement: a real session's chain (written through the
// actual flight recorder, not hand-built JSON), exported by the real CLI
// command, validated against the real OTLP-JSON schema shape — span names
// asserted, per the task text — rather than only unit-testing
// internal/otlp's Build function against synthetic input.
func TestExportOTLPValidatesAgainstTheRealOTLPJSONShape(t *testing.T) {
	code0 := 0
	allowedFalse := false
	_, sessionID, path := chainOf(t, []recorder.Event{
		{Type: recorder.TypeSessionStart, Arch: "aarch64", Image: "dev", Kelyfos: "v1.1.0"},
		{Type: recorder.TypeSessionReady, BootMS: 500},
		{Type: recorder.TypeCommandStart, Call: "c1", Cmd: []string{"echo", "a result"}, Via: "exec"},
		{Type: recorder.TypeCommandExit, Call: "c1", Code: &code0, DurationMS: 100},
		{Type: recorder.TypeEgressAttempt, Host: "evil.example", Port: 443,
			Allowed: &allowedFalse, Reason: "not_in_allowlist"},
		{Type: recorder.TypeSessionEnd, Reason: "shutdown", DurationMS: 5000},
	})

	dest := filepath.Join(t.TempDir(), "trace.json")
	if err := exportOTLPSession(sessionID, path, dest); err != nil {
		t.Fatalf("exportOTLPSession: %v", err)
	}

	blob, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading the export: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("the export is not valid JSON: %v", err)
	}

	resourceSpans, _ := doc["resourceSpans"].([]interface{})
	if len(resourceSpans) == 0 {
		t.Fatal("no resourceSpans in the export")
	}
	rs0 := resourceSpans[0].(map[string]interface{})
	resource, _ := rs0["resource"].(map[string]interface{})
	if resource == nil {
		t.Fatal("resourceSpans[0].resource missing")
	}
	scopeSpans, _ := rs0["scopeSpans"].([]interface{})
	if len(scopeSpans) == 0 {
		t.Fatal("no scopeSpans")
	}
	spans, _ := scopeSpans[0].(map[string]interface{})["spans"].([]interface{})
	if len(spans) == 0 {
		t.Fatal("no spans in the export")
	}

	var names []string
	sawInvokeAgent, sawExecuteTool, sawEgressEvent := false, false, false
	for _, raw := range spans {
		s := raw.(map[string]interface{})
		name, _ := s["name"].(string)
		names = append(names, name)
		if name == "invoke_agent" {
			sawInvokeAgent = true
			events, _ := s["events"].([]interface{})
			for _, re := range events {
				e := re.(map[string]interface{})
				if strings.HasPrefix(e["name"].(string), "kelyfos.egress.") {
					sawEgressEvent = true
				}
			}
		}
		if strings.HasPrefix(name, "execute_tool") {
			sawExecuteTool = true
		}

		traceID, _ := s["traceId"].(string)
		if len(traceID) != 32 || !otlpHexID.MatchString(traceID) {
			t.Errorf("span %q: traceId %q is not 32 lowercase-hex characters", name, traceID)
		}
		spanID, _ := s["spanId"].(string)
		if len(spanID) != 16 || !otlpHexID.MatchString(spanID) {
			t.Errorf("span %q: spanId %q is not 16 lowercase-hex characters", name, spanID)
		}
		if _, ok := s["kind"].(float64); !ok {
			t.Errorf("span %q: kind is not a JSON number (OTLP/JSON enums MUST be integers)", name)
		}
		for _, field := range []string{"startTimeUnixNano", "endTimeUnixNano"} {
			if _, ok := s[field].(string); !ok {
				t.Errorf("span %q: %s is not a JSON string", name, field)
			}
		}
	}

	if !sawInvokeAgent {
		t.Errorf("no invoke_agent span in the export; spans were: %v", names)
	}
	if !sawExecuteTool {
		t.Errorf("no execute_tool span in the export; spans were: %v", names)
	}
	if !sawEgressEvent {
		t.Error("no kelyfos.egress.* span event on the invoke_agent span")
	}

	// No guest-influenced string reaches an OTLP attribute unescaped: no raw
	// control byte anywhere in the file the export command actually wrote.
	for i, b := range blob {
		if b < 0x20 && b != '\n' && b != '\t' && b != '\r' {
			t.Fatalf("raw control byte 0x%02x at offset %d in the written export file", b, i)
		}
	}
}

// TestExportOTLPIsOneWayAndNeverTouchesTheRecord: the file the OTLP export
// reads from is untouched — D59's own boundary, checked rather than trusted.
func TestExportOTLPIsOneWayAndNeverTouchesTheRecord(t *testing.T) {
	code0 := 0
	_, sessionID, path := chainOf(t, []recorder.Event{
		{Type: recorder.TypeSessionStart},
		{Type: recorder.TypeCommandStart, Call: "c1", Cmd: []string{"echo", "hi"}, Via: "exec"},
		{Type: recorder.TypeCommandExit, Call: "c1", Code: &code0},
		{Type: recorder.TypeSessionEnd, Reason: "shutdown"},
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "trace.json")
	if err := exportOTLPSession(sessionID, path, dest); err != nil {
		t.Fatalf("exportOTLPSession: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the flight recorder file changed after an OTLP export — it must be read-only from this path")
	}

	// And the chain still verifies — untouched by both the read and by the
	// otlp package, which is D59's whole point stated as a running check
	// rather than an assertion about intent.
	if _, _, err := recorder.Verify(mustOpen(t, path)); err != nil {
		t.Fatalf("the chain no longer verifies after an OTLP export: %v", err)
	}
}

func mustOpen(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
