package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-17/A2 — the door F13(b) did not reach: serve-mcp's OWN chain.
//
// F13(b) wired Broken() into every loop that holds a machine open, and gave
// serve-mcp a per-sandbox watcher because it has no such loop. What it did not
// give it is any watch on the server's own audit session — the chain carrying
// every mcp.host.call and mcp.host.result. A full disk or one damaged line
// latched that recorder and the server went on answering tool calls with every
// mcp.host.* event silently refused: an agent creating machines, running
// commands and spending credentials, and an outward lane saying none of it
// happened. closeAudit also never called EndBroken, so the chain simply stopped
// mid-session with nothing saying why.

// The operator hears it once, however many calls are refused. Separate from the
// test above because it needs the writer seam, which does not exist on the
// parent commit.
func TestA2_TheOperatorIsToldOnceHoweverManyCallsAreRefused(t *testing.T) {
	rec, _ := brokenRecorder(t)
	var said strings.Builder
	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec, errw: &said}

	for i := 0; i < 5; i++ {
		if res := s.callTool(&mcp.CallToolParams{Name: "sandbox_exec"}); !res.IsError {
			t.Fatal("a tool call was answered while nothing was being recorded")
		}
	}
	if n := strings.Count(said.String(), "flight recorder stopped"); n != 1 {
		t.Errorf("the operator was told %d times across five refused calls, want once:\n%s",
			n, said.String())
	}
}

// The operator is told when it happens rather than at the next call, because a
// serve-mcp process is idle between calls and sometimes for hours.
func TestA2_TheAuditWatcherSaysSoWithoutWaitingForACall(t *testing.T) {
	rec, _ := brokenRecorder(t)
	// Locked, because the watcher writes it from its own goroutine while this
	// test reads it — a strings.Builder shared that way is a data race in the
	// fixture, not in the code under test, and `make test` does not run -race
	// so it would have sat here unseen.
	said := &lockedWriter{}
	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec, errw: said}

	stopped := make(chan struct{})
	go s.watchAudit(rec, stopped)

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(said.String(), "flight recorder stopped") {
		if time.Now().After(deadline) {
			t.Fatal("two seconds after the server's chain broke, nothing had been said")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stopped)

	// A watcher on an intact recorder waits, and goes away when told to.
	root := t.TempDir()
	ok, err := recorder.Open(root, "a2watch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ok.Close() })
	done := make(chan struct{})
	quit := make(chan struct{})
	go func() { s.watchAudit(ok, quit); close(done) }()
	close(quit)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("the watcher did not stop when its box did; it would outlive the server")
	}
}

// And it stops the watcher, so a serve-mcp process that shuts down does not
// leave a goroutine behind per session it opened.
func TestA2_CloseAuditStopsTheWatcher(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	root := t.TempDir()
	rec, err := recorder.Open(root, "a2stop")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	s := &hostServer{boxes: map[string]*servedBox{}, audit: rec, auditID: "a2stop", auditStopped: stopped}

	done := make(chan struct{})
	go func() { s.watchAudit(rec, stopped); close(done) }()
	s.closeAudit()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the audit watcher outlived closeAudit")
	}
	if s.auditStopped != nil {
		t.Error("closeAudit left the stop channel in place; a second call would close it twice")
	}
}

// lockedWriter is an io.Writer a goroutine may write while a test reads it.
type lockedWriter struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}
