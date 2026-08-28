package recorder

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// fillTheDisk makes the next write to any file this process holds fail the
// way a full filesystem does, by pinning RLIMIT_FSIZE to a size the file has
// already reached. A real ENOSPC needs a filesystem a test cannot create
// without root; EFBIG is the same shape of answer from the same syscall — the
// kernel refusing to grow the file — and it is the only one reproducible
// hermetically.
//
// The limit is set exactly AT the file's current size on purpose: a write
// that starts below the limit is served short (the kernel writes up to the
// limit and then reports the error), which would leave a torn line in the
// chain and confuse what is being measured here with a separate problem. At
// the limit the write returns 0 bytes and EFBIG, so the file on disk is
// byte-for-byte what it was and the only thing that happened is that one
// event did not get recorded.
//
// The limit is process-wide, so the returned restore is called immediately
// after the one Append being measured, and again from t.Cleanup in case the
// test fails in between. Nothing else in this package writes a file during
// that window.
func fillTheDisk(t *testing.T, at int64) func() {
	t.Helper()
	var old unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &old); err != nil {
		t.Skipf("RLIMIT_FSIZE is not readable here (%v); this test needs it to simulate a full disk", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: uint64(at), Max: old.Max}); err != nil {
		t.Skipf("RLIMIT_FSIZE is not settable here (%v); this test needs it to simulate a full disk", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &old); err != nil {
			t.Fatalf("restoring RLIMIT_FSIZE: %v", err)
		}
	}
	t.Cleanup(restore)
	return restore
}

func chainSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Size()
}

// TestF13_AFailedAppendStopsTheRecorder is F13(a) stated as behaviour, using
// nothing but the API that already existed when the finding was written — so
// it runs, and fails, on the commit before the fix.
//
// The scenario: a session is running, the disk fills under it, one event
// cannot be written, and then the pressure goes away. Before the fix the
// recorder carried on as though nothing had happened. The chain that results
// verifies cleanly — every digest correct, every seq consecutive — and reads
// as a session in which the command that was running simply never produced
// any output. There is no line anywhere saying an event was lost, and
// `kelyfos verify` is green on it.
//
// That is the failure this test refuses: once the record has lost an event,
// the recorder must be finished. A shorter chain that says it stopped is
// evidence; a complete-looking chain with a hole in it is worse than no chain
// at all, because somebody will rely on it.
func TestF13_AFailedAppendStopsTheRecorder(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "f13")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rec.Close()

	for _, e := range []Event{
		{Type: TypeSessionStart, Image: "base", Arch: "aarch64", Kelyfos: "test"},
		{Type: TypeCommandStart, Call: "c1", Cmd: []string{"/bin/sh", "-c", "curl https://api.example.com/"}, Via: "exec"},
	} {
		if err := rec.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Type, err)
		}
	}

	path := Path(root, "f13")
	restore := fillTheDisk(t, chainSize(t, path))
	lost := Event{Type: TypeCommandOutput, Call: "c1", Stream: "stdout", Data: "d2hhdCB0aGUgZ3Vlc3QgcHJpbnRlZAo=", Bytes: 24}
	appendErr := rec.Append(lost)
	restore()
	if appendErr == nil {
		t.Fatal("the write was supposed to fail with the disk full; it did not, so this test proved nothing")
	}
	t.Logf("the event that was lost: %v", appendErr)

	// The disk has room again. Every door in host/ discards Append's error, so
	// on the unfixed recorder the session simply carries on from here.
	if err := rec.Append(Event{Type: TypeCommandExit, Call: "c1", DurationMS: 12}); err == nil {
		t.Error("the recorder accepted an event after it had already failed to record one — " +
			"the resulting chain is a session with a silent hole in it, and it verifies clean")
	}
	if err := rec.Append(Event{Type: TypeSessionEnd, Reason: "shutdown", DurationMS: 900}); err == nil {
		t.Error("the recorder wrote a session.end after losing an event — the chain now claims " +
			"to be a complete record of a session it stopped recording partway through")
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("reading the chain back: %v", err)
	}
	for _, e := range events {
		if e.Type == TypeCommandOutput {
			t.Fatalf("the event that failed to write is on the chain anyway: %+v", e)
		}
	}
	// Whatever it holds, it must not hold the two events written after the
	// failure — and it must not read as a session that ended normally.
	for _, e := range events {
		if e.Type == TypeCommandExit || (e.Type == TypeSessionEnd && e.Reason == "shutdown") {
			t.Fatalf("event %d (%s) was recorded after the recorder had already lost an event", e.Seq, e.Type)
		}
	}
}

// TestF13_BrokenFiresAndTheChainSaysWhyItStops is the other half: the signal
// a run loop watches, the error an operator is shown, and the one line that
// distinguishes a chain cut short from a session still open.
//
// The failure here is arranged so a small write can still get past it — the
// limit is lifted before the shutdown path runs, which is the realistic case
// of an operator who freed some space, or a burst of writes that filled a
// filesystem with delayed allocation. That is the case where the record can
// still say why it stops, and it must.
func TestF13_BrokenFiresAndTheChainSaysWhyItStops(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "f13b")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rec.Close()

	select {
	case <-rec.Broken():
		t.Fatal("Broken fired on a recorder that has recorded nothing yet")
	default:
	}
	if seq, ferr := rec.Failure(); seq != 0 || ferr != nil {
		t.Fatalf("Failure on an intact recorder = (%d, %v), want (0, nil)", seq, ferr)
	}

	for _, e := range []Event{
		{Type: TypeSessionStart, Image: "base", Arch: "aarch64", Kelyfos: "test"},
		{Type: TypeCommandStart, Call: "c1", Cmd: []string{"/bin/sh", "-c", "echo hi"}, Via: "exec"},
	} {
		if err := rec.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Type, err)
		}
	}

	path := Path(root, "f13b")
	restore := fillTheDisk(t, chainSize(t, path))
	if err := rec.Append(Event{Type: TypeCommandOutput, Call: "c1", Stream: "stdout", Data: "aGkK", Bytes: 3}); err == nil {
		restore()
		t.Fatal("the write was supposed to fail with the disk full; it did not")
	}
	restore()

	select {
	case <-rec.Broken():
	default:
		t.Fatal("Broken did not fire after an Append failed — nothing tells the run loop to stop the machine")
	}
	seq, ferr := rec.Failure()
	if ferr == nil {
		t.Fatal("Failure reported no error after an Append failed")
	}
	// The event that was lost is seq 3: session.start and command.start are
	// the two that made it.
	if seq != 3 {
		t.Errorf("Failure reported seq %d, want 3 — the sequence number of the event that was lost", seq)
	}

	// A second failure must not replace the first. What broke the recording
	// is the useful answer; the errors that follow are consequences.
	first := ferr
	if err := rec.Append(Event{Type: TypeCommandExit, Call: "c1"}); err == nil {
		t.Fatal("a broken recorder accepted an event")
	}
	if _, again := rec.Failure(); again != first {
		t.Errorf("the latched error changed from %v to %v — only the first failure is the cause", first, again)
	}

	// The shutdown path gets the epitaph in now that the disk has room.
	if err := rec.EndBroken(); err != nil {
		t.Fatalf("EndBroken: %v", err)
	}
	if err := rec.EndBroken(); err != nil {
		t.Fatalf("EndBroken is not idempotent: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, head, verr := Verify(bytes.NewReader(blob))
	if verr != nil {
		t.Fatalf("a chain cut short by a recorder failure must still verify: %v", verr)
	}
	if head == "" {
		t.Error("Verify returned no chain head")
	}
	if n != 3 {
		t.Fatalf("Verify counted %d events, want 3 (session.start, command.start, and the session.end that says why)", n)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Type != TypeSessionEnd {
		t.Fatalf("the chain's last event is %q — a truncated chain with no session.end is "+
			"indistinguishable from a session that is still open", last.Type)
	}
	if !strings.HasPrefix(last.Reason, "recorder failed at seq 3: ") {
		t.Errorf("session.end reason = %q, want it to name the recorder failure and the seq it happened at", last.Reason)
	}
	if !strings.Contains(last.Reason, "file too large") {
		t.Errorf("session.end reason = %q, want it to carry the underlying error", last.Reason)
	}
	if len(last.Reason) > maxFailureReason+64 {
		t.Errorf("session.end reason is %d bytes — a field an erasure does not redact must stay bounded", len(last.Reason))
	}
	// Only one, however many times the shutdown path asks.
	ends := 0
	for _, e := range events {
		if e.Type == TypeSessionEnd {
			ends++
		}
	}
	if ends != 1 {
		t.Errorf("the chain carries %d session.end events, want 1", ends)
	}
}

// TestF13_ENOSPCLatchesTheRecorder is the finding's own words — "fill the
// disk" — with the errno the kernel actually returns for it. /dev/full is a
// character device whose every write fails with ENOSPC, which is the only way
// to get that exact error out of a real syscall without a filesystem this
// test cannot create.
func TestF13_ENOSPCLatchesTheRecorder(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Skipf("no /dev/full here (%v); TestF13_AFailedAppendStopsTheRecorder covers the same latch", err)
	}
	defer full.Close()
	rec := newRecorder(full, "enospc")

	err = rec.Append(Event{Type: TypeSessionStart, Image: "base"})
	if err == nil {
		t.Fatal("a write to /dev/full succeeded")
	}
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("Append error = %v, want ENOSPC", err)
	}
	select {
	case <-rec.Broken():
	default:
		t.Fatal("ENOSPC did not break the recorder")
	}
	if _, ferr := rec.Failure(); !errors.Is(ferr, syscall.ENOSPC) {
		t.Errorf("the latched error is %v, want ENOSPC", ferr)
	}
	if err := rec.Append(Event{Type: TypeCommandStart, Call: "c1"}); err == nil {
		t.Error("the recorder kept accepting events with the disk full")
	}
}

// TestF13_ACorruptChainLatchesTheRecorder is the permanent half of the
// finding: catchUp refuses a chain it cannot parse (recorder.go's catchUp),
// and before the fix that refusal was returned to seventy-seven callers who
// dropped it. Damaging one byte of a live session's file stopped the
// recording and told nobody.
//
// The damage is done by a second process's worth of bytes rather than by
// flipping one in place, because a flipped byte inside a JSON string is still
// valid JSON — what catchUp actually refuses is a line that does not parse,
// which is what a writer killed mid-write leaves behind.
func TestF13_ACorruptChainLatchesTheRecorder(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "f13c")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rec.Close()
	if err := rec.Append(Event{Type: TypeSessionStart, Image: "base"}); err != nil {
		t.Fatal(err)
	}

	path := Path(root, "f13c")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"v":1,"seq":2,"ts":"2026-01-0`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if err := rec.Append(Event{Type: TypeCommandStart, Call: "c1"}); err == nil {
		t.Fatal("Append succeeded onto a chain that no longer parses")
	}
	select {
	case <-rec.Broken():
	default:
		t.Fatal("a corrupt chain did not break the recorder — the session goes on being unrecorded")
	}
	seq, ferr := rec.Failure()
	if ferr == nil || !strings.Contains(ferr.Error(), "corrupt") {
		t.Errorf("the latched error is %v, want the corruption named", ferr)
	}
	if seq != 2 {
		t.Errorf("Failure reported seq %d, want 2", seq)
	}
	// The epitaph cannot be written here — writing it means reading the chain
	// first, and the chain is what is broken. That is the accepted case: the
	// latch and Broken are what the run loop acts on.
	if err := rec.EndBroken(); err == nil {
		t.Error("EndBroken claimed to have written a session.end onto a chain that does not parse")
	}
}

// TestF13_ANilRecorderNeverBreaks: recording disabled is not recording
// broken. A run loop selects on Broken unconditionally, so a nil Recorder has
// to hand back a channel that never fires rather than a closed one — a closed
// one would tear down every sandbox started with recording off.
func TestF13_ANilRecorderNeverBreaks(t *testing.T) {
	var rec *Recorder
	if err := rec.Append(Event{Type: TypeSessionStart}); err != nil {
		t.Fatalf("Append on a nil Recorder: %v", err)
	}
	select {
	case <-rec.Broken():
		t.Fatal("Broken fired on a nil Recorder — recording disabled would shut every sandbox down")
	default:
	}
	if seq, err := rec.Failure(); seq != 0 || err != nil {
		t.Errorf("Failure on a nil Recorder = (%d, %v), want (0, nil)", seq, err)
	}
	if err := rec.EndBroken(); err != nil {
		t.Errorf("EndBroken on a nil Recorder: %v", err)
	}
}
