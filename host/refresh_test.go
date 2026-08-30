package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-9: --export against a live session, and --refresh keeping it current.
// These tests exercise the actual polling loop (host/log.go's
// refreshExportSession) against a real flight recorder growing under it,
// rather than against a description of what the loop is supposed to do — the
// same standard the done-checklist itself asks the manual verification to
// meet, run here so it is not only asserted once by hand.

// waitForFile polls path until want returns true on its contents, or fails
// the test after a generous bound. Polling rather than a fixed sleep: the
// loop under test writes on its own schedule, and a fixed sleep either races
// a slow CI runner or wastes time on a fast one.
func waitForFile(t *testing.T, path string, want func(string) bool) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			last = string(b)
			if want(last) {
				return last
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to reach the expected state; last content:\n%s", path, last)
	return ""
}

func TestWriteRefreshedReportDropsTheTagOnceTheSessionHasEnded(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	running, err := os.ReadFile(recorder.Path(root, "s1"))
	if err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "r.html")
	ended, n, err := writeRefreshedReport(dest, "s1", running, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ended {
		t.Fatal("a running session was reported as ended")
	}
	if n != 1 {
		t.Fatalf("expected 1 event rendered, got %d", n)
	}
	page, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `<meta http-equiv="refresh" content="3">`) {
		t.Errorf("a running session's export carries no refresh tag:\n%s", page)
	}

	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	stopped, err := os.ReadFile(recorder.Path(root, "s1"))
	if err != nil {
		t.Fatal(err)
	}
	ended, _, err = writeRefreshedReport(dest, "s1", stopped, nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !ended {
		t.Fatal("a session carrying session.end was not reported as ended")
	}
	page, err = os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(page), `http-equiv="refresh"`) {
		t.Errorf("the final export after session.end still carries a refresh tag:\n%s", page)
	}
}

// The full loop: a session file that grows while refreshExportSession is
// running against it, a real change (a command recorded mid-loop) picked up
// with nobody calling exportSession again, and a clean stop once
// session.end lands — no socket, no listener, just this process rewriting
// dest on a timer and reading it back to check its own work.
func TestRefreshExportSessionFollowsAGrowingSessionAndStopsWhenItEnds(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	path := recorder.Path(root, "s1")
	dest := filepath.Join(t.TempDir(), "watch.html")

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- refreshExportSession(ctx, "s1", path, dest, "", 150*time.Millisecond) }()

	waitForFile(t, dest, func(s string) bool { return strings.Contains(s, "still running") })

	// A real change to the session's state — not re-running the export by
	// hand, which is exactly what the recipe and the done-checklist demand.
	if err := rec.Append(recorder.Event{Type: recorder.TypeCommandStart, Cmd: []string{"echo", "hi"}}); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, dest, func(s string) bool { return strings.Contains(s, "echo hi") })

	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refreshExportSession returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("refreshExportSession did not stop on its own once the session ended")
	}

	final, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(final), `http-equiv="refresh"`) {
		t.Errorf("the loop's own final write still carries a refresh tag:\n%s", final)
	}
}

// Ctrl-C (or SIGTERM) has to stop the loop even when the session never ends
// on its own — a team a person is done watching, not one that finished.
func TestRefreshExportSessionStopsOnContextCancelWithNoSessionEnd(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	path := recorder.Path(root, "s1")
	dest := filepath.Join(t.TempDir(), "watch.html")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- refreshExportSession(ctx, "s1", path, dest, "", 150*time.Millisecond) }()

	waitForFile(t, dest, func(s string) bool { return strings.Contains(s, "still running") })
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refreshExportSession returned an error on cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refreshExportSession did not stop after its context was cancelled")
	}

	// A tab left open on dest polls forever on whatever tag its last rewrite
	// carried. Ctrl-C is not session.end, but a page nothing will update
	// again should still stop asking to be refreshed.
	final, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(final), `http-equiv="refresh"`) {
		t.Errorf("the loop's final write after a context cancel still carries a refresh tag:\n%s", final)
	}
}

// "/dev/null" as both path and dest is deliberate: the interval check has to
// reject before either is ever touched, so a passing test here can only mean
// the floor fired — not, say, atomicWriteReport failing to CreateTemp under
// /dev (which a non-root user gets EACCES on, and which returns non-nil
// regardless of the interval, quietly masking a removed floor check). That
// is checked, not assumed: matching the error message, not just err != nil.
func TestRefreshExportSessionRejectsANonPositiveInterval(t *testing.T) {
	err := refreshExportSession(context.Background(), "s1", "/dev/null", "/dev/null", "", 0)
	if err == nil {
		t.Fatal("a zero --refresh-every was accepted")
	}
	if !strings.Contains(err.Error(), "--refresh-every must be at least") {
		t.Fatalf("rejected for the wrong reason (not the interval floor): %v", err)
	}
}

// A positive interval that is merely tiny is not "the caller wants a fast
// refresh" — measured at over a full CPU-second of syscalls per wall-second,
// against a <meta refresh> tag whose own content is whole seconds. Below
// minRefreshInterval is rejected the same way zero is.
func TestRefreshExportSessionRejectsAnIntervalBelowTheFloor(t *testing.T) {
	err := refreshExportSession(context.Background(), "s1", "/dev/null", "/dev/null", "", time.Nanosecond)
	if err == nil {
		t.Fatal("a 1ns --refresh-every was accepted")
	}
	if !strings.Contains(err.Error(), "--refresh-every must be at least") {
		t.Fatalf("1ns rejected for the wrong reason (not the interval floor): %v", err)
	}

	err = refreshExportSession(context.Background(), "s1", "/dev/null", "/dev/null", "", 50*time.Millisecond)
	if err == nil {
		t.Fatal("a 50ms --refresh-every was accepted, below the 100ms floor")
	}
	if !strings.Contains(err.Error(), "--refresh-every must be at least") {
		t.Fatalf("50ms rejected for the wrong reason (not the interval floor): %v", err)
	}
}

// A destination the loop cannot write to (here: a directory that does not
// exist, the same fault the one-shot --export already exits 1 on) is not a
// parse race that resolves itself on the next tick. Before this fix the loop
// printed "export not yet valid, retrying" forever; it must instead return
// the error and stop, the way --export does for the identical fault.
func TestRefreshExportSessionStopsOnAPermanentWriteFailure(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	path := recorder.Path(root, "s1")
	dest := filepath.Join(t.TempDir(), "no-such-directory", "watch.html")

	done := make(chan error, 1)
	go func() { done <- refreshExportSession(context.Background(), "s1", path, dest, "", 150*time.Millisecond) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("refreshExportSession returned no error against an unwritable destination")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refreshExportSession retried a permanent write failure forever instead of stopping")
	}
}

// recorder.Open creates events.jsonl with O_CREATE before the first Append
// lands, so a refresh that starts in that window sees a file that exists and
// is empty. bytes.Equal(nil, nil) is true, so without the `wrote` guard the
// loop's own "nothing new since last time" branch matches on tick one and
// never writes dest at all — not an error, not a retry message, nothing: the
// loop just sits there, forever, on a session that has genuinely started.
//
// The fix renders the empty chain immediately, same as the one-shot --export
// already does for an empty record — a report saying "nothing happened yet"
// is a valid, honest state to show, and it means a browser tab opened early
// sees *something* rather than a blank page nothing will ever fill in. This
// pins that: dest exists (with 0 events) before anything is ever recorded,
// and updates once real content lands.
func TestRefreshExportSessionRecoversFromAnEmptyChainFile(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	path := recorder.Path(root, "s1")
	dest := filepath.Join(t.TempDir(), "watch.html")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- refreshExportSession(ctx, "s1", path, dest, "", 150*time.Millisecond) }()

	// The empty chain is written on its own — this is the tick-one write the
	// bug used to skip via bytes.Equal(nil, nil). "still running" is true of
	// an empty-but-unended chain too (Summary.Ended is unset either way), so
	// existence — not content — is what distinguishes the fix from the bug:
	// before it, dest was never created at all.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(dest); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for dest to be written from the empty chain file")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	waitForFile(t, dest, func(s string) bool { return strings.Contains(s, "still running") })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("refreshExportSession returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refreshExportSession did not stop after its context was cancelled")
	}
}
