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
