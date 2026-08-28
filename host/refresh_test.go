package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
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
	go func() { done <- refreshExportSession(ctx, "s1", path, dest, "", 20*time.Millisecond) }()

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
	go func() { done <- refreshExportSession(ctx, "s1", path, dest, "", 20*time.Millisecond) }()

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
}

func TestRefreshExportSessionRejectsANonPositiveInterval(t *testing.T) {
	if err := refreshExportSession(context.Background(), "s1", "/dev/null", "/dev/null", "", 0); err == nil {
		t.Fatal("a zero --refresh-every was accepted")
	}
}
