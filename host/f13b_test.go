package main

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/exitcode"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// P7-17/F13(b) — the run loop stops a machine whose recorder has failed.
//
// The recorder latches on first failure and refuses everything after it, and
// until this change nothing acted on that. So a sandbox whose recorder had died
// went on executing commands and making egress with nothing recorded and nobody
// told — which is verbatim the harm F13 describes, and what docs/events.md said
// in bold rather than claiming otherwise.

// brokenRecorder returns a real, open recorder that has already latched.
//
// It breaks it the way the finding's permanent half does (internal/recorder's
// TestF13_ACorruptChainLatchesTheRecorder): damage the chain under the open
// file, so catchUp refuses it and the next Append fails. That needs only the
// package's exported surface, which is the point — this is host/, and if a
// caller here can break a recorder the same way a full disk does, the wiring
// under test is the wiring that runs.
func brokenRecorder(t *testing.T) (*recorder.Recorder, string) {
	rec, path, _ := brokenRecorderRepairable(t)
	return rec, path
}

// brokenRecorderRepairable is the same, plus the way back: repair() takes the
// damage off the file again.
//
// That models the case EndBroken exists for and is not a convenience — "by then
// the machine is down, so whatever was holding the disk may have let go" is its
// own doc comment. A recorder broken by damage that is still there cannot write
// its epitaph either, which is correct and is why the two tests below repair
// first.
func brokenRecorderRepairable(t *testing.T) (rec *recorder.Recorder, path string, repair func()) {
	t.Helper()
	root := t.TempDir()
	rec, err := recorder.Open(root, "f13b")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart, Image: "base"}); err != nil {
		t.Fatal(err)
	}
	path = recorder.Path(root, "f13b")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	intact := fi.Size()

	// A second process's worth of bytes that is not a chain line.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("this is not a chain line\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := rec.Append(recorder.Event{Type: recorder.TypeCommandStart, Call: "c1"}); err == nil {
		t.Fatal("the recorder accepted an event after its chain was damaged")
	}
	select {
	case <-rec.Broken():
	default:
		t.Fatal("a failed Append did not break the recorder")
	}
	return rec, path, func() {
		if err := os.Truncate(path, intact); err != nil {
			t.Fatal(err)
		}
	}
}

// The line an operator gets, and the reason the session ends with. Both halves
// matter: a machine that stops without saying why is the same silence the
// finding is about, one layer along.
func TestF13b_TheOperatorIsToldWhichEventWasLost(t *testing.T) {
	rec, _ := brokenRecorder(t)
	var out strings.Builder

	reason := recorderFailed(rec, &out)
	if reason != "recorder_failed" {
		t.Errorf("session.end reason = %q, want recorder_failed", reason)
	}
	got := out.String()
	seq, ferr := rec.Failure()
	if seq == 0 {
		t.Error("Failure reported no sequence number")
	}
	for _, want := range []string{
		"flight recorder stopped",
		"stopping the machine",
		"not being recorded",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the operator's line does not say %q:\n%s", want, got)
		}
	}
	// The event that was LOST, and the error, both in the line.
	if !strings.Contains(got, "event "+itoa(seq)) {
		t.Errorf("the line does not name the lost event %d:\n%s", seq, got)
	}
	if !strings.Contains(got, ferr.Error()) {
		t.Errorf("the line does not say why (%v):\n%s", ferr, got)
	}
}

// A nil recorder is recording disabled, not a broken one. Broken() returns nil
// and a receive on nil blocks forever, so a select that watches it simply never
// fires — no nil guard at the call site, which is the design.
func TestF13b_ADisabledRecorderNeverFires(t *testing.T) {
	var rec *recorder.Recorder
	select {
	case <-rec.Broken():
		t.Fatal("a nil recorder's Broken channel fired")
	case <-time.After(20 * time.Millisecond):
	}
	if err := rec.EndBroken(); err != nil {
		t.Errorf("EndBroken on a nil recorder: %v", err)
	}
}

// EndBroken puts the "why the record stops here" line on the chain, and the
// teardown paths call it before their own session.end. Called twice — which is
// what happens when a run loop sees the break and the deferred teardown runs
// after it — it writes one line, not two.
func TestF13b_EndBrokenWritesTheEpitaphOnceAndIsSafeTwice(t *testing.T) {
	rec, path, repair := brokenRecorderRepairable(t)
	repair()

	if err := rec.EndBroken(); err != nil {
		t.Fatalf("EndBroken: %v", err)
	}
	// Twice, which is what happens when a run loop sees the break and the
	// deferred teardown runs after it.
	if err := rec.EndBroken(); err != nil {
		t.Fatalf("second EndBroken: %v", err)
	}
	_ = rec.Close()

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(blob), "recorder failed at seq"); n != 1 {
		t.Errorf("the chain carries %d epitaphs, want exactly 1:\n%s", n, blob)
	}
}

// The teardown that every `kelyfos run` takes calls EndBroken before its own
// session.end. Asserted on the file the run would have written, through the
// same sequence the deferred block performs.
func TestF13b_TheTeardownGetsTheEpitaphOntoTheChain(t *testing.T) {
	rec, path, repair := brokenRecorderRepairable(t)
	repair()
	// endSession is what every teardown in this CLI calls — run.go's defer,
	// the team's endRecord, and serve-mcp's box close. Driven rather than
	// replicated, so removing EndBroken from it turns this red.
	endSession(rec, "recorder_failed", nil)

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "recorder failed at seq") {
		t.Errorf("the teardown did not put the epitaph on the chain:\n%s", blob)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// serve-mcp has no run loop, so the wait is a goroutine per box. What it must
// do is what a run loop does: stop the machine, tell the operator, and tell the
// client the next time it asks — rather than leave a sandbox running with
// nothing recorded, or answer "no such sandbox" for one this server stopped
// itself.
func TestF13b_ServeMCPStopsServingABoxWhoseRecorderFailed(t *testing.T) {
	rec, _ := brokenRecorder(t)
	s := &hostServer{boxes: map[string]*servedBox{}}
	// A half-built box: close() is nil-safe for every piece, which is the case
	// a restore that failed after its network came up already produces.
	b := &servedBox{}
	b.setRec(rec)
	s.boxes["abc1234"] = b

	go s.watchRecorder("abc1234", b)

	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		_, still := s.boxes["abc1234"]
		s.mu.Unlock()
		if !still {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the box is still being served two seconds after its recorder broke")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Deregistering is not stopping. The box has to have been torn down —
	// close() is what does that, and it clears b.rec on its way out, which is
	// the observable this fixture has. Without this assertion, deleting
	// b.close() from watchRecorder left the suite green while the machine kept
	// running unrecorded: F13's own harm, surviving in the one door with no run
	// loop.
	if rec, _ := b.watchable(); rec != nil {
		t.Error("the box was deregistered and never torn down: its recorder is still set, " +
			"so close() did not run and the machine is still up, unrecorded")
	}

	// And the client is told what happened, rather than that it never existed.
	_, err := s.box("abc1234")
	if err == nil {
		t.Fatal("a stopped box is still reachable")
	}
	for _, want := range []string{"flight recorder failed", "stopped"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the client's error does not say %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "no sandbox") {
		t.Errorf("a box this server stopped reads as one that never existed: %v", err)
	}
}

// The watcher goes away with the box rather than outliving it: a normal
// sandbox_stop must not leave a goroutine waiting on a channel nobody will
// close, and stopWatching must be safe to call twice, which close() and a
// second close() both do.
func TestF13b_TheWatcherStopsWithTheBox(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "healthy")
	if err != nil {
		t.Fatal(err)
	}
	b := &servedBox{}
	b.setRec(rec)

	parked := make(chan struct{})
	done := make(chan struct{})
	s := &hostServer{boxes: map[string]*servedBox{"live": b}}
	go func() {
		close(parked)
		s.watchRecorder("live", b)
		close(done)
	}()
	<-parked
	// The watcher has to actually reach its select before the box is closed,
	// or this passes for the wrong reason: watchable() returns (nil, nil) on an
	// already-closed box and the goroutine returns without ever having waited.
	// That is how the first version of this test stayed green.
	time.Sleep(50 * time.Millisecond)

	// Through close(), which is the path an ordinary sandbox_stop takes — NOT
	// stopWatching() by hand, which is what this test did when it was written
	// and is why deleting the stopWatching call from close() left it green.
	b.close("shutdown")
	b.close("shutdown") // idempotent: more than one path reaches it

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher outlived the box: a sandbox_stop left a goroutine parked " +
			"in watchRecorder on a channel nobody will close")
	}
	s.mu.Lock()
	_, still := s.boxes["live"]
	s.mu.Unlock()
	if !still {
		t.Error("a box whose recorder never broke was deregistered anyway")
	}
}

// And the consequence, counted rather than argued: forty create/stop cycles
// must leave no goroutine behind. This is what the reviewer measured when the
// stopWatching call was deleted from close() — forty leaked, all parked in
// watchRecorder — and it is a stronger statement than one box's watcher
// returning, because a leak that only shows up under repetition is exactly the
// leak nobody notices.
func TestF13b_RepeatedCreateAndStopLeaksNoWatchers(t *testing.T) {
	root := t.TempDir()
	before := runtime.NumGoroutine()

	const cycles = 40
	for i := 0; i < cycles; i++ {
		rec, err := recorder.Open(root, "cycle"+itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		b := &servedBox{}
		b.setRec(rec)
		s := &hostServer{boxes: map[string]*servedBox{"b": b}}
		go s.watchRecorder("b", b)
		time.Sleep(time.Millisecond)
		b.close("shutdown")
	}

	// Goroutines exit asynchronously, so give them a bounded moment to.
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if grew := runtime.NumGoroutine() - before; grew > 2 {
		t.Errorf("%d goroutines leaked across %d create/stop cycles; each sandbox_stop left "+
			"its watcher parked in watchRecorder", grew, cycles)
	}
}

// And the watcher is started where a machine is registered, not at the three
// places a recorder is published — so every door that builds a sandbox on this
// server gets it. Driven through adopt, which is that single registration
// point, on a box with no machine behind it (close() is nil-safe for every
// piece, which is the state a restore that failed after its network came up
// already produces).
func TestF13b_AdoptStartsTheWatcher(t *testing.T) {
	rec, _ := brokenRecorder(t)
	s := &hostServer{boxes: map[string]*servedBox{}, max: 4}
	b := &servedBox{sb: &sandbox.Sandbox{}}
	b.sb.State.ID = "adopted1"
	b.setRec(rec)

	if err := s.adopt(b); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		_, still := s.boxes["adopted1"]
		s.mu.Unlock()
		if !still {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("adopt did not start a recorder watcher: the box is still served " +
				"two seconds after its recorder broke")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The trailing-command form sets its own session.end reason and exit code by a
// separate literal from the interactive form's, and nothing covered it: the
// whole `if recorderBroke { … }` could be neutralised with the suite green,
// leaving `kelyfos run -- cmd` on a broken recorder writing reason
// "command_exited" and the child's status — the record misdescribing the run,
// which is the RECORD checklist's own concern and what docs/events.md now
// promises against.
func TestF13b_ABrokenRecorderDecidesHowTheRunIsDescribed(t *testing.T) {
	for _, c := range []struct {
		name            string
		childCode       int
		timedOut        string
		broke, oom      bool
		reason          string
		announced, exit int
	}{
		{name: "the ordinary case", childCode: 0, reason: "command_exited", announced: 0, exit: 0},
		{name: "the child's own failure", childCode: 3, reason: "command_exited", announced: 3, exit: 3},
		{name: "a timeout beats the child", childCode: 0, timedOut: "max_runtime",
			reason: "timeout", announced: exitTimedOut, exit: exitTimedOut},
		{name: "a broken recorder beats a clean child", childCode: 0, broke: true,
			reason: "recorder_failed", announced: exitcode.Fail, exit: exitcode.Fail},
		{name: "a broken recorder beats the child's own failure", childCode: 3, broke: true,
			reason: "recorder_failed", announced: exitcode.Fail, exit: exitcode.Fail},
		{name: "a broken recorder beats a timeout", childCode: 0, timedOut: "max_runtime", broke: true,
			reason: "recorder_failed", announced: exitcode.Fail, exit: exitcode.Fail},
		{name: "an OOM upgrades a clean exit", childCode: 0, oom: true,
			reason: "command_exited", announced: 0, exit: exitOOMKilled},
		{name: "an OOM does not overwrite a failure", childCode: 3, oom: true,
			reason: "command_exited", announced: 3, exit: 3},
		{name: "an OOM does not overwrite a broken recorder", childCode: 0, broke: true, oom: true,
			reason: "recorder_failed", announced: exitcode.Fail, exit: exitcode.Fail},
	} {
		t.Run(c.name, func(t *testing.T) {
			reason, announced, code := commandRunOutcome(c.childCode, c.timedOut, c.broke, c.oom)
			if reason != c.reason {
				t.Errorf("session.end reason = %q, want %q", reason, c.reason)
			}
			if announced != c.announced {
				t.Errorf("the `exited N` line says %d, want %d", announced, c.announced)
			}
			if code != c.exit {
				t.Errorf("exit code = %d, want %d", code, c.exit)
			}
		})
	}
}
