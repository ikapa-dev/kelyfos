package main

import (
	"os"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
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

	// sandbox_list is the cheapest tool that answers something a refusal cannot
	// be mistaken for: an empty list, with IsError unset.
	res := s.callTool(&mcp.CallToolParams{Name: "sandbox_list"})
	if res == nil || !res.IsError {
		t.Fatalf("a tool call was answered while nothing was being recorded: %+v", res)
	}
	seq, ferr := rec.Failure()
	body := toolText(res)
	for _, want := range []string{
		"flight recorder stopped",
		"refusing every tool call",
		itoa(seq),
		ferr.Error(),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal does not carry %q:\n%s", want, body)
		}
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
