package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// A bridge that closes with a tool call still outstanding used to exit 0
// regardless: answerOutstanding already wrote the caller a synthetic error
// and a stderr line saying so, but the process itself reported success, so a
// wrapper script or supervisor checking $? after `kelyfos mcp` saw nothing
// wrong (F6) — indistinguishable from every call having been answered and the
// client simply hanging up. It now exits non-zero whenever that happens,
// whatever closed the connection: the guest process exiting, the sandbox
// tearing down, or a guest MCP session ending on a frame it could not parse.
func TestAnswerOutstandingFailsTheProcessWhenACallWasNeverAnswered(t *testing.T) {
	rec, err := recorder.Open(t.TempDir(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	obs := newObserver(rec, "")
	obs.fromClient([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
		`"params":{"name":"exec","arguments":{"command":"echo hi"}}}`))
	// No matching fromGuest call: the guest never answered id 1, exactly the
	// state the bridge is in when its connection to the guest ends mid-call.

	var out bytes.Buffer
	err = answerOutstanding(&out, obs)
	if err == nil {
		t.Fatal("expected a non-nil error so the process exits non-zero, got nil")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code == 0 {
		t.Errorf("expected a non-zero *exitError, got %#v", err)
	}

	var reply struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
		t.Fatalf("stdout did not carry a synthetic answer: %v (%q)", err, out.String())
	}
	if string(reply.ID) != "1" || !reply.Result.IsError {
		t.Errorf("expected a tool error answering id 1, got %q", out.String())
	}
}

// The ordinary case — every call got answered — must keep exiting 0. Failing
// the process whenever anything was ever outstanding, even briefly and
// answered, would make a normal session that finishes cleanly look broken.
func TestAnswerOutstandingSucceedsWhenNothingIsPending(t *testing.T) {
	rec, err := recorder.Open(t.TempDir(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	obs := newObserver(rec, "")

	var out bytes.Buffer
	if err := answerOutstanding(&out, obs); err != nil {
		t.Errorf("expected nil with nothing pending, got %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected nothing written with nothing pending, got %q", out.String())
	}
}
