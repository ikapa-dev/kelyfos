package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/sandbox"
	"time"
)

// The audit of 2026-09-01's A15: sandbox_exec with timeout_ms = MaxInt64
// multiplied out to a negative Duration, which the guest path absorbed into a
// silent ten-second grace kill — the asked contract and the delivered one
// disagreed, with nothing on the record saying so. The door now refuses above
// the documented ceiling, naming the bound, before anything is resolved.

func TestA15_TheAuditReproTimeoutIsRefused(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)

	// The audit's exact frame, with a sandbox id that does not exist: the
	// timeout refusal must come first, so bad arguments are refused before
	// anything is resolved.
	res := s.toolExec(json.RawMessage(
		`{"sandbox":"nosuch","command":"sleep 30","timeout_ms":9223372036854775807}`))
	if !res.IsError {
		t.Fatal("a MaxInt64 timeout_ms was accepted")
	}
	text := res.Content[0].Text
	for _, want := range []string{"timeout_ms 9223372036854775807", "24 hours"} {
		if !strings.Contains(text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, text)
		}
	}
}

// A negative timeout_ms is not the default and is not a duration: it is refused
// by name (audit 2026-09-01, L1), naming the value and the range it is outside.
func TestA15_ANegativeTimeoutIsRefusedByName(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	res := s.toolExec(json.RawMessage(`{"sandbox":"nosuch","command":"true","timeout_ms":-5}`))
	if !res.IsError {
		t.Fatal("a negative timeout_ms was accepted")
	}
	text := res.Content[0].Text
	for _, want := range []string{"timeout_ms -5", "negative", "1 to 86400000"} {
		if !strings.Contains(text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, text)
		}
	}
	// Zero is the one non-positive value that means something: it stays the
	// default and is not refused here, so this call fails at the box lookup
	// rather than at the timeout.
	res = s.toolExec(json.RawMessage(`{"sandbox":"nosuch","command":"true","timeout_ms":0}`))
	if strings.Contains(res.Content[0].Text, "negative") {
		t.Errorf("timeout_ms 0 was treated as negative:\n%s", res.Content[0].Text)
	}
}

// The description a model reads states both the 24-hour ceiling and that a
// negative value is refused (audit 2026-09-01, A15/L1).
func TestA15_TheTimeoutDescriptionStatesTheCeiling(t *testing.T) {
	var desc string
	for _, tool := range hostToolDefinitions() {
		if tool.Name == "sandbox_exec" {
			desc = tool.InputSchema.Properties["timeout_ms"].Description
		}
	}
	if desc == "" {
		t.Fatal("sandbox_exec has no timeout_ms description")
	}
	for _, want := range []string{"86400000", "24", "negative"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the timeout_ms description does not state %q:\n%s", want, desc)
		}
	}
}

// The ceiling is real and the conversion under it cannot wrap.
func TestA15_TheExecTimeoutCeilingIsDocumentedAndBounded(t *testing.T) {
	if sandbox.MaxExecTimeout != 24*60*60*1e9 {
		t.Errorf("MaxExecTimeout = %v, want 24h", sandbox.MaxExecTimeout)
	}
	// The largest timeout_ms the door accepts converts to a Duration the
	// library clamps to, without wrapping: the two numbers must agree.
	max := int64(sandbox.MaxExecTimeout / time.Millisecond)
	if time.Duration(max)*time.Millisecond != sandbox.MaxExecTimeout {
		t.Errorf("converting the ceiling to ms and back does not round-trip: %d ms", max)
	}
}
