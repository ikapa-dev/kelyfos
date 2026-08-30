package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-17/A2 — the half of this item that COMPILES on the parent commit.
//
// The tests here touch nothing this change added to the hostServer struct, so
// they build against fb62db8 and fail there on behaviour rather than at the
// linker. The rest of the item's tests need the watcher, the stop channel and
// the writer seam, none of which exist there; those live in a2_test.go and
// their parent result is a build failure, which is stated rather than dressed
// up as a behavioural one.

// The guarantee. A tool call after the server's chain has stopped is refused,
// and refused BEFORE anything is dispatched.
func TestA2_ABrokenServerAuditRefusesEveryToolCall(t *testing.T) {
	rec, _ := brokenRecorder(t)
	// Deliberately no test seam in this one, so it COMPILES on the parent
	// commit and fails there behaviourally rather than at the linker. The
	// operator's own line is asserted separately, below.
	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec}

	// sandbox_exec, not sandbox_list: the three tools that can only make the
	// unrecorded window smaller are deliberately still answered (D76), so a
	// test that used one of those would measure the exemption rather than the
	// refusal.
	res := s.callTool(&mcp.CallToolParams{Name: "sandbox_exec"})
	if res == nil || !res.IsError {
		t.Fatalf("a tool call was answered while nothing was being recorded: %+v", res)
	}
	seq, ferr := rec.Failure()
	body := toolText(res)
	for _, want := range []string{
		"flight recorder stopped",
		"refusing tool calls",
		itoa(seq),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not carry %q:\n%s", want, body)
		}
	}
	// And it carries NOTHING of the recorder's own error. On the failure this
	// whole path exists for — a full disk — that error is os.File.Write's
	// *os.PathError and carries the absolute path of the recorder file,
	// unbounded; internal/recorder clamps it to 160 bytes for the on-chain
	// reason field and nothing clamped it here. The client needs one fact and
	// gets it: stop asking. The operator gets the error, on stderr, where the
	// path is useful and the audience can act on it (P7-17/A2, review round).
	if strings.Contains(body, ferr.Error()) {
		t.Errorf("the refusal hands the client the recorder's own error, which on a full disk "+
			"is an unbounded absolute host path:\n%s", body)
	}

}

// The other half of the same sentence: an intact chain refuses nothing. Without
// this, `return mcp.Errorf(...)` unconditionally would satisfy the test above.
func TestA2_AnIntactServerAuditRefusesNothing(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "a2intact")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec}

	res := s.callTool(&mcp.CallToolParams{Name: "sandbox_list"})
	if res == nil || res.IsError {
		t.Fatalf("an ordinary tool call was refused on an intact chain: %+v", res)
	}
	// And a server with no audit chain at all — recording disabled — is not a
	// broken one.
	none := &hostServer{boxes: map[string]*servedBox{}}
	if res := none.callTool(&mcp.CallToolParams{Name: "sandbox_list"}); res.IsError {
		t.Errorf("a server with no audit recorder refused a call: %s", toolText(res))
	}
}

// The refusal happens BEFORE anything is dispatched, which is the whole of the
// guarantee and was the half nothing tested: moving the check to after the
// dispatch returns a byte-identical result to the client, so the tool genuinely
// runs — a machine boots, a command executes, a credential is spent — and the
// client is told it did not. The review moved it and the whole suite stayed
// green (P7-17/A2, review round).
func TestA2_ARefusedCallIsNeverDispatched(t *testing.T) {
	rec, _ := brokenRecorder(t)
	var ran []string
	s := &hostServer{
		boxes:      map[string]*servedBox{},
		audit:      rec,
		dispatched: func(tool string) { ran = append(ran, tool) },
	}

	for _, tool := range []string{"sandbox_run", "sandbox_exec", "sandbox_write_file",
		"sandbox_snapshot", "sandbox_fork", "team_up"} {
		if res := s.callTool(&mcp.CallToolParams{Name: tool}); !res.IsError {
			t.Errorf("%s was answered while nothing was being recorded", tool)
		}
	}
	if len(ran) != 0 {
		t.Fatalf("these tools were dispatched on a server whose chain had stopped: %v\n"+
			"  The refusal has to run before the dispatch, or the machine boots, the command\n"+
			"  runs, the credential is spent — and the client is told none of it happened.", ran)
	}

	// And the three D76 exempts DO dispatch, or the exemption is a refusal
	// wearing a different message.
	for _, tool := range []string{"sandbox_list", "sandbox_stop", "team_down"} {
		_ = s.callTool(&mcp.CallToolParams{Name: tool})
	}
	if len(ran) != 3 {
		t.Errorf("the tools that can only make the unrecorded window smaller were not "+
			"dispatched; ran = %v (D76)", ran)
	}
}

// The exemption, from the outside: a machine can still be found and stopped by
// a client that has just been told its calls are not being recorded.
func TestA2_TheToolsThatShrinkTheWindowAreStillAnswered(t *testing.T) {
	rec, _ := brokenRecorder(t)
	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec}

	// A half-built box, which close() is nil-safe for.
	b := &servedBox{}
	s.boxes["abc1234"] = b

	if res := s.callTool(&mcp.CallToolParams{Name: "sandbox_list"}); res.IsError {
		t.Errorf("sandbox_list was refused: %s", toolText(res))
	}
	arg := json.RawMessage(`{"sandbox":"abc1234"}`)
	if res := s.callTool(&mcp.CallToolParams{Name: "sandbox_stop", Arguments: arg}); res.IsError {
		t.Errorf("sandbox_stop was refused, so a machine this agent started cannot be "+
			"stopped: %s", toolText(res))
	}
	s.mu.Lock()
	_, still := s.boxes["abc1234"]
	s.mu.Unlock()
	if still {
		t.Error("sandbox_stop was answered and the box is still registered, so the call was " +
			"not really dispatched")
	}
}

// closeAudit is a teardown like every other in this CLI, and every other one
// calls EndBroken through endSession. This one did not, so the record of a
// serve-mcp session whose chain had failed ended mid-session with nothing
// saying why.
func TestA2_CloseAuditPutsTheEpitaphOnTheChain(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	rec, path, repair := brokenRecorderRepairable(t)
	// Repaired first, for the reason EndBroken's own doc comment gives: by the
	// time a teardown runs the machine is down and whatever was holding the
	// disk may have let go. A recorder broken by damage that is still there
	// cannot write its epitaph either, which is correct.
	repair()

	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec, auditID: "a2close"}
	s.closeAudit()

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "recorder failed at seq") {
		t.Errorf("closeAudit did not put the epitaph on the chain:\n%s", blob)
	}
	if s.audit != nil {
		t.Error("closeAudit left the recorder set")
	}
}

// toolText is the text a tool result carries, for assertions.
func toolText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}
