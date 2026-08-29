package shim

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// P7-17/A2 — this package had zero references to Broken().
//
// F13(b) wired every loop that holds a machine open and gave serve-mcp a
// per-box watcher because it has no such loop. The shim has no such loop either
// and got neither, so an E2B-shim sandbox whose flight recorder failed kept
// running: commands executed, egress made, nothing recorded, nobody told. It is
// the one door in this product that answers to a network socket.

// brokenRecorder returns a real, open recorder that has already latched, plus
// the way back.
//
// Damaged the way the finding's permanent half is (internal/recorder's
// TestF13_ACorruptChainLatchesTheRecorder): bytes appended under the open file,
// so catchUp refuses the chain and the next Append fails. Only the package's
// exported surface, which is the point — if this package can break a recorder
// the way a full disk does, the wiring under test is the wiring that runs.
func brokenRecorder(t *testing.T) (rec *recorder.Recorder, path string, repair func()) {
	t.Helper()
	root := t.TempDir()
	rec, err := recorder.Open(root, "a2shim")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart, Image: "dev"}); err != nil {
		t.Fatal(err)
	}
	path = recorder.Path(root, "a2shim")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	intact := fi.Size()

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

// The whole of it in one observable: the box stops being served, and the chain
// carries the epitaph — which can only be there if close() ran and called
// EndBroken.
func TestA2_TheShimStopsASandboxWhoseRecorderFailed(t *testing.T) {
	rec, path, repair := brokenRecorder(t)
	// Repaired before the watcher fires, for the reason EndBroken's own doc
	// comment gives: by the time a teardown runs the machine is down and
	// whatever was holding the disk may have let go. Broken() is already closed,
	// so the watcher still fires at once.
	repair()

	s := New(Policy{})
	// A half-built box, which is what a boot that failed after its recorder was
	// opened already produces. Every piece of close() is nil-guarded.
	b := &box{rec: rec, stopped: make(chan struct{})}
	s.mu.Lock()
	s.boxes["7a02fe01"] = b
	s.mu.Unlock()

	go s.watchRecorder("7a02fe01", b)

	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		_, still := s.boxes["7a02fe01"]
		s.mu.Unlock()
		if !still {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the shim was still serving a sandbox three seconds after its recorder broke")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Deregistering is not stopping. Two separate observables, because they
	// have two separate causes and an assertion whose message names the wrong
	// one is the shape of every test this task found unable to fail.
	//
	// First: close() ran at all. It takes the stop channel out of the box on
	// its way in, so a nil there is the machine having been torn down rather
	// than merely dropped from the map.
	b.wmu.Lock()
	left := b.stopped
	b.wmu.Unlock()
	if left != nil {
		t.Fatal("the box was deregistered and never torn down: close() did not run, so the " +
			"machine is still up and unrecorded")
	}
	// Second: close() called EndBroken. Without it the chain of a session whose
	// recorder failed ends mid-session with nothing saying why, because the
	// ordinary session.end append is refused like every other.
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "recorder failed at seq") {
		t.Errorf("close() ran and did not put the epitaph on the chain, so the record stops "+
			"mid-session with no reason in it:\n%s", blob)
	}
}

// A watcher on an intact recorder waits, and goes away when the box does.
func TestA2_TheShimsWatcherStopsWithItsBox(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "a2live")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Policy{})
	b := &box{rec: rec, stopped: make(chan struct{})}

	done := make(chan struct{})
	go func() { s.watchRecorder("live1", b); close(done) }()

	b.close("shutdown")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher outlived the box it was watching")
	}

	// A second close is a no-op rather than a double close of the channel,
	// because DELETE /sandboxes/{id} and the watcher can both reach it.
	b.close("shutdown")

	blob, err := os.ReadFile(recorder.Path(root, "a2live"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "recorder failed at seq") {
		t.Error("EndBroken wrote an epitaph onto an intact chain; it must be a no-op there")
	}
	if !strings.Contains(string(blob), `"session.end"`) {
		t.Errorf("the ordinary session.end is missing from an intact chain:\n%s", blob)
	}
}
