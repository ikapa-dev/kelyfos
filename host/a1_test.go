package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// The independent audit of 2026-09-01 (A1): a sandbox_fork count near MaxInt64
// wrapped the fleet ceiling's `have+n`, walked past it, and panicked the server
// in make([]result, n) — killing the process and orphaning every sandbox it
// owned. These tests hold the three places the fix landed, plus the panic net
// that makes any future tool panic a refusal instead of a death.

// The audit's own repro, verbatim: one frame, one running sandbox on the books,
// and the largest signed integer as the count. It must come back as a
// structured refusal naming the bound — and the server must still be serving.
func TestForkCountOverflowIsRefusedNotFatal(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	// The repro needed ≥1 running sandbox: with none, the ceiling refused at 0
	// and nothing wrapped. One on the books is what made have+n overflow.
	s.boxes["already-running"] = &servedBox{}
	res := s.toolFork(json.RawMessage(`{"name":"default","count":9223372036854775807}`))
	if !res.IsError {
		t.Fatal("MaxInt64 forks were accepted")
	}
	for _, want := range []string{"[fork.count]", "256", "9223372036854775807"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.Content[0].Text)
		}
	}
	// The server is alive enough to answer again — the old path died here.
	if res := s.toolList(); res.IsError {
		t.Errorf("the server did not survive the refused call: %s", res.Content[0].Text)
	}
}

// The same frame through the JSON-RPC door the audit drove, so the answer a
// client sees — a tool result with isError set, and then a ping answered — is
// the answer the repro got a crash instead of.
func TestForkCountOverflowThroughServe(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	s.boxes["already-running"] = &servedBox{}

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sandbox_fork",` +
			`"arguments":{"name":"default","count":9223372036854775807}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sandbox_list"}}`,
	}, "\n") + "\n"
	var out strings.Builder
	if err := s.serve(strings.NewReader(in), &out); err != nil {
		t.Fatalf("serve returned an error: %v", err)
	}
	// Tool calls are served on their own goroutines, so answers are ordered
	// by nothing but their ids; collect them all and index by id.
	byID := map[string]*mcp.CallToolResult{}
	dec := json.NewDecoder(strings.NewReader(out.String()))
	for len(byID) < 3 {
		var resp struct {
			ID     json.RawMessage     `json:"id"`
			Result *mcp.CallToolResult `json:"result"`
			Error  *mcp.Error          `json:"error"`
		}
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("the server stopped answering after 3 calls, %d answered: %v\n%s",
				len(byID), err, out.String())
		}
		if resp.Error != nil {
			t.Fatalf("call %s came back as a protocol error: %v", resp.ID, resp.Error)
		}
		byID[string(resp.ID)] = resp.Result
	}
	refused := byID["1"]
	if refused == nil || !refused.IsError {
		t.Fatalf("the overflow call was not refused:\n%s", out.String())
	}
	if !strings.Contains(refused.Content[0].Text, "[fork.count]") {
		t.Errorf("the refusal is not the catalog one:\n%s", refused.Content[0].Text)
	}
	// ids 2 and 3 answered: the process lived.
	if byID["2"] == nil || byID["3"] == nil {
		t.Errorf("the ping or the list after the refused call got no answer:\n%s", out.String())
	}
}

// room is the ceiling itself. It must refuse by subtraction — the addition it
// replaced wrapped — whatever the ask.
func TestRoomCannotWrap(t *testing.T) {
	s := &hostServer{max: 4, boxes: map[string]*servedBox{"one": {}}}
	if err := s.room(math.MaxInt64); err == nil {
		t.Fatal("MaxInt64 more sandboxes fit a fleet of 4")
	} else if !strings.Contains(err.Error(), "[budget.sandboxes]") {
		t.Errorf("the refusal is not the catalog one: %v", err)
	}
	if err := s.room(3); err != nil {
		t.Errorf("3 more fit 4-with-1-running, but: %v", err)
	}
	// And a bookkeeping accident — more boxes than the ceiling says — is
	// refused for everything, never underflowed into permission.
	full := &hostServer{max: 1, boxes: map[string]*servedBox{"a": {}, "b": {}}}
	if err := full.room(1); err == nil {
		t.Fatal("a server over its own ceiling took another machine")
	}
}

// CheckForkSpace multiplied the count by a workspace size, and the same count
// made the product read negative — smaller than any free space, so the space
// check waved the fork through.
func TestCheckForkSpaceCannotWrap(t *testing.T) {
	dir := t.TempDir()
	if err := sandbox.CheckForkSpace(dir, math.MaxInt64, 1<<30); err == nil {
		t.Fatal("MaxInt64 forks of a 1 GiB workspace passed the space check")
	} else if !strings.Contains(err.Error(), "workspace copies") {
		t.Errorf("the refusal does not say what it is about: %v", err)
	}
	if err := sandbox.CheckForkSpace(dir, 2, 1<<10); err != nil {
		t.Errorf("2 KiB of copies was refused: %v", err)
	}
}

// The panic net: no tool, however broken, ends the process or leaves its call
// unanswered in the record. dispatchTool has nothing left that panics on its
// own — that was the finding — so the test fires the seam.
func TestRunCallPanicNetHolds(t *testing.T) {
	root := t.TempDir()
	audit, err := recorder.Open(root, "a1net")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = audit.Close() }()
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes,
		boxes: map[string]*servedBox{}, audit: audit}
	s.crashTool = func(tool string) bool { return tool == "sandbox_list" }

	res := s.callTool(&mcp.CallToolParams{Name: "sandbox_list"})
	if !res.IsError {
		t.Fatal("a panicking tool came back as success")
	}
	if !strings.Contains(res.Content[0].Text, "internal error") ||
		!strings.Contains(res.Content[0].Text, "still serving") {
		t.Errorf("the recovery does not say what happened or that the server lived:\n%s",
			res.Content[0].Text)
	}

	// The record answers the call it recorded: one mcp.host.call, and one
	// mcp.host.result carrying the recovered refusal — the pair a reader of
	// the transcript is owed, which a panic that skipped `done` took away.
	events := readRecord(t, root, "a1net")
	var calls, results int
	for _, ev := range events {
		switch ev.Type {
		case recorder.TypeMCPHostCall:
			calls++
		case recorder.TypeMCPHostResult:
			results++
			if ev.Outcome != "error" {
				t.Errorf("the result event does not say the call failed: %v", ev.Outcome)
			}
		}
	}
	if calls != 1 || results != 1 {
		t.Errorf("the record has %d call(s) and %d result(s), want one of each", calls, results)
	}

	// The seam is off again; the same tool answers normally.
	s.crashTool = nil
	if res := s.toolList(); res.IsError {
		t.Errorf("sandbox_list was left broken after the net fired: %s", res.Content[0].Text)
	}
}

// readRecord reads a closed session's chain back as events.
func readRecord(t *testing.T, root, id string) []recorder.Event {
	t.Helper()
	blob, err := os.ReadFile(recorder.Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	var events []recorder.Event
	for _, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var ev recorder.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			t.Fatalf("a record line did not parse: %v", err)
		}
		events = append(events, ev)
	}
	return events
}
