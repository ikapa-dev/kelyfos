package shim

import (
	"os"
	"strings"
	"sync"
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
	said := &lockedWriter{}
	s.errw = said
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

	// Third: the operator was told. "Nobody told" is half of the harm F13
	// describes, and until the review this was the half the shim asserted
	// nothing about — the watcher wrote to os.Stderr directly, and replacing
	// the whole Fprintf with something that compiles left the package green
	// (P7-17/A2, review round).
	told := said.String()
	for _, want := range []string{"7a02fe01", "flight recorder", "stopping it"} {
		if !strings.Contains(told, want) {
			t.Errorf("the operator's line does not say %q:\n%s", want, told)
		}
	}
	if !strings.Contains(told, itoa(seqOf(t, rec))) {
		t.Errorf("the operator's line does not name the event that was lost:\n%s", told)
	}

	// Fourth: the SDK is told WHY, rather than that the sandbox never existed.
	// serve-mcp has kept a reason since F13(b), for the same stated purpose;
	// the shim deleted the box and kept none, so DELETE answered a bare 404 and
	// the envd routes answered "no sandbox has been created through this shim".
	s.mu.Lock()
	why := s.lostReason("7a02fe01")
	s.mu.Unlock()
	if !strings.Contains(why, "flight recorder failed") {
		t.Errorf("the shim kept no reason for a sandbox it stopped itself: %q", why)
	}
	if _, err := s.only(); err == nil || !strings.Contains(err.Error(), "flight recorder failed") {
		t.Errorf("an envd call after the last sandbox was stopped says %v, which does not say "+
			"why it is gone", err)
	}
}

// close() takes the watcher out FIRST, and the comment says why: otherwise a
// watcher firing mid-teardown starts a second concurrent close, and only
// stopWatching is mutex-guarded — sb.Shutdown, proxy.Close, net.Down and
// slice.Close are not. Nothing held that ordering until the review moved it to
// a defer and the package stayed green (P7-17/A2, review round).
func TestA2_CloseStopsTheWatcherBeforeItTearsAnythingDown(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "a2order")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Policy{})
	b := &box{rec: rec, stopped: make(chan struct{})}

	// The watcher is parked on a recorder that never breaks, so the only thing
	// that can end it is close() taking its channel away.
	ended := make(chan struct{})
	go func() { s.watchRecorder("a2order", b); close(ended) }()

	// A recorder whose Close has run is the observable for "the teardown got
	// past the watcher": if stopWatching ran first, the watcher is already
	// gone by the time anything else in close() happens.
	b.close("shutdown")
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher was still parked after close() returned; it was not stopped first, " +
			"so a break during teardown would start a second concurrent close")
	}
	b.wmu.Lock()
	left := b.stopped
	b.wmu.Unlock()
	if left != nil {
		t.Error("close() left the stop channel in place")
	}
}

// seqOf is the sequence number of the event a recorder lost.
func seqOf(t *testing.T, rec *recorder.Recorder) int {
	t.Helper()
	seq, _ := rec.Failure()
	return seq
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
