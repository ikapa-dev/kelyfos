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
