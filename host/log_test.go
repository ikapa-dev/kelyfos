package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// renderEvent runs one event through the replay renderer and gives back the
// line a reader would see. printEvent writes to stdout because that is what a
// replay is; the pipe is the only way to read back what it said.
func renderEvent(t *testing.T, e recorder.Event) string {
	t.Helper()
	line, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	printEvent(line, false)
	os.Stdout = saved
	w.Close()
	out, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The record already distinguishes the two ways a shell ends — an exit frame,
// and a connection that stopped without one — and the replay has to as well.
// The second is written as code 1 with a reason (host/shell.go), and a reader
// shown only the code cannot tell a dead supervisor from a command that ran and
// failed. That is the same conflation the exit path was fixed for, one layer up
// in the view.
func TestTheReplayTellsADeadSupervisorFromAShellThatExited(t *testing.T) {
	one, two := 1, 1
	dead := renderEvent(t, recorder.Event{
		TS: "2026-08-24T10:00:00.000Z", Type: recorder.TypeShellEnd, Code: &one,
		Reason: "the supervisor closed the connection without an exit frame", DurationMS: 320})
	failed := renderEvent(t, recorder.Event{
		TS: "2026-08-24T10:00:00.000Z", Type: recorder.TypeShellEnd, Code: &two, DurationMS: 320})

	if dead == failed {
		t.Fatalf("a dead supervisor and a shell that exited 1 replay identically:\n  %s", dead)
	}
	if !strings.Contains(dead, "without an exit frame") {
		t.Errorf("the reason the shell ended is not in the line a reader sees:\n  %s", dead)
	}
	if !strings.Contains(failed, "exit 1") {
		t.Errorf("a shell that exited 1 did not say so:\n  %s", failed)
	}
}

// A signalled shell is the other thing the record knows and the line did not
// say: 137 on its own does not tell a reader the shell was killed.
func TestTheReplaySaysWhichSignalEndedAShell(t *testing.T) {
	code := 137
	line := renderEvent(t, recorder.Event{
		TS: "2026-08-24T10:00:00.000Z", Type: recorder.TypeShellEnd, Code: &code,
		Signal: "SIGKILL", DurationMS: 90})

	if !strings.Contains(line, "SIGKILL") {
		t.Errorf("the signal that ended the shell is not in the line a reader sees:\n  %s", line)
	}
}

// P7-13/F2: printEvent's own doc precedent (shell.end's Reason, P6-28) is
// "a compromised guest editing the audit view as it is read" — an escape
// sequence in a guest- or operator-influenced field rewriting lines of the
// replay already printed. Every case below carries the same shape and, until
// this fix, printed the parsed Go string straight into fmt.Printf with no
// escaping at all. hostile carries an ESC byte (0x1b) plus a literal
// carriage return, both of which a naive terminal replay would act on
// rather than display.
func TestTheReplayEscapesControlBytesOnEveryFieldItPrints(t *testing.T) {
	const hostile = "\x1bnormal\rlooking\x1btext"
	code := 1

	cases := []struct {
		name string
		e    recorder.Event
	}{
		{"session.start reason", recorder.Event{Type: recorder.TypeSessionStart, Reason: hostile}},
		{"session.end reason", recorder.Event{Type: recorder.TypeSessionEnd, Reason: hostile}},
		{"command.start argv", recorder.Event{Type: recorder.TypeCommandStart, Cmd: []string{hostile}}},
		{"command.exit error", recorder.Event{Type: recorder.TypeCommandExit, Code: &code,
			Error: &recorder.EvError{Kind: "e", Message: hostile}}},
		{"file.write path", recorder.Event{Type: recorder.TypeFileWrite, Path: hostile}},
		{"egress.attempt host", recorder.Event{Type: recorder.TypeEgressAttempt, Host: hostile}},
		{"egress.attempt reason", recorder.Event{Type: recorder.TypeEgressAttempt, Reason: hostile}},
		{"secret.use name", recorder.Event{Type: recorder.TypeSecretUse, Name: hostile}},
		{"secret.use host", recorder.Event{Type: recorder.TypeSecretUse, Host: hostile}},
		{"team.message agent", recorder.Event{Type: recorder.TypeTeamMessage, Agent: hostile}},
		{"team.message peer", recorder.Event{Type: recorder.TypeTeamMessage, Peer: hostile}},
		{"team.refused reason", recorder.Event{Type: recorder.TypeTeamRefused, Reason: hostile}},
		{"team.store agent", recorder.Event{Type: recorder.TypeTeamStore, Agent: hostile}},
		{"team.spawn reason", recorder.Event{Type: recorder.TypeTeamSpawn, Outcome: "refused", Reason: hostile}},
		{"resource.oom comm", recorder.Event{Type: recorder.TypeResourceOOM, Comm: hostile}},
		{"mcp.host_call name", recorder.Event{Type: recorder.TypeMCPHostCall, Name: hostile}},
		{"mcp.host_result error", recorder.Event{Type: recorder.TypeMCPHostResult,
			Error: &recorder.EvError{Message: hostile}}},
		{"plugin.call name", recorder.Event{Type: recorder.TypePluginCall, Name: hostile}},
		{"plugin.crash reason", recorder.Event{Type: recorder.TypePluginCrash, Reason: hostile}},
		{"shell.start path", recorder.Event{Type: recorder.TypeShellStart, Path: hostile}},
		{"forward.accept peer", recorder.Event{Type: recorder.TypeForwardAccept, Peer: hostile}},
		{"forward.accept reason", recorder.Event{Type: recorder.TypeForwardAccept, Reason: hostile}},
		{"run.review path", recorder.Event{Type: recorder.TypeRunReview, Path: hostile}},
		{"session.pause name", recorder.Event{Type: recorder.TypeSessionPause, Name: hostile}},
		{"session.resume name", recorder.Event{Type: recorder.TypeSessionResume, Name: hostile}},
		{"session.resume reason", recorder.Event{Type: recorder.TypeSessionResume, Reason: hostile}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.e.TS = "2026-08-28T10:00:00.000Z"
			line := renderEvent(t, c.e)
			if strings.ContainsRune(line, 0x1b) {
				t.Errorf("a raw ESC byte reached the replay:\n  %q", line)
			}
			if strings.Contains(line, "\rlooking") {
				t.Errorf("a raw carriage return reached the replay unescaped:\n  %q", line)
			}
		})
	}
}
