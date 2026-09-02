package recorder

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The audit of 2026-09-01's A14: a live writer's catchUp chained onto
// whatever it found at the file tail without re-verifying it, and the chain
// head was published nowhere but the chain itself. Two closes:
//
//   - catchUp now verifies every line it would chain onto, with the same rules
//     Verify applies, and latches on a mismatch;
//   - every append writes an out-of-band anchor (head.json) that CheckHead
//     compares against a verified chain, so a wholesale rewrite that does not
//     also update the anchor is detectable.

func a14Recorder(t *testing.T, root, id string) *Recorder {
	t.Helper()
	r, err := Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// a14Anchor is the sequence every reader of a record now follows — a locked
// snapshot, a chain verify, then the anchor check — collapsed for the tests
// that assert what the anchor says. It replaces the old CheckHead, which read
// the chain and the anchor unlocked and in separate steps.
func a14Anchor(t *testing.T, root, id string) (AnchorReport, error) {
	t.Helper()
	snap, err := ReadSnapshot(root, id)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	n, head, err := Verify(bytes.NewReader(snap.Chain))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return snap.CheckAnchor(n, head)
}

func a14Event(seq int, name string) Event {
	return Event{Type: TypeSessionStart, Name: name, Reason: "a14"}
}

// A same-uid writer appends a correctly-shaped line whose prev does not follow
// the chain. The next Append must refuse and latch, not extend the forgery.
func TestA14_AForgedTailIsLatchedNotExtended(t *testing.T) {
	root, id := t.TempDir(), "a14forged"
	r := a14Recorder(t, root, id)
	if err := r.Append(a14Event(1, "first")); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	// The forgery: well-formed JSON, a plausible seq, a prev and a hash that
	// do not belong to this chain. DigestOfLine-style recomputation on the
	// attacker's side is impossible to satisfy for free — the hash they carry
	// is not the hash of their own line.
	forgery := map[string]any{
		"v": 1, "seq": 2, "ts": "2026-09-01T00:00:00.000Z", "sandbox": id,
		"type": "resource.oom", "source": "guest",
		"prev": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	blob, _ := json.Marshal(forgery)
	f, err := os.OpenFile(Path(root, id), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(blob, '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Reopen: catchUp runs against the forged tail before the first Append.
	r2 := a14Recorder(t, root, id)
	defer r2.Close()
	err = r2.Append(a14Event(3, "after-forgery"))
	if err == nil {
		t.Fatal("an Append was accepted onto a forged tail")
	}
	if !strings.Contains(err.Error(), "does not follow event") && !strings.Contains(err.Error(), "has been modified") {
		t.Errorf("the refusal does not name the forgery:\n%v", err)
	}
	// Latched: nothing further is recorded.
	if err := r2.Append(a14Event(4, "after-latch")); err == nil {
		t.Error("the recorder kept writing after the latch")
	}
}

// The anchor: a chain rewritten wholesale (truncated, with the kept events'
// claims recomputed) verifies on its own — the documented keyless limit — but
// no longer agrees with what the anchor last recorded.
func TestA14_TheAnchorDetectsAWholesaleRewrite(t *testing.T) {
	root, id := t.TempDir(), "a14anchor"
	r := a14Recorder(t, root, id)
	for i := 0; i < 3; i++ {
		if err := r.Append(Event{Type: TypeSessionStart, Name: "event", Reason: "a14"}); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()

	// What a reader sees after the appends: chain and anchor agree.
	blob, err := os.ReadFile(Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	report, err := a14Anchor(t, root, id)
	if err != nil {
		t.Fatalf("an intact chain failed its own anchor: %v", err)
	}
	if report.State != AnchorMatches {
		t.Fatalf("an intact chain's anchor did not match: %v", report)
	}

	// The attacker truncates to the first event and leaves it — a chain that
	// still verifies, ending one event earlier than the anchor remembers.
	first := bytes.Split(blob, []byte("\n"))[0]
	if err := os.WriteFile(Path(root, id), append(first, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(bytes.NewReader(append(first, '\n'))); err != nil {
		t.Fatalf("the truncated chain does not verify, so the anchor is not what caught this: %v", err)
	}
	report, err = a14Anchor(t, root, id)
	if err == nil {
		t.Fatal("a wholesale rewrite was not detected")
	}
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Errorf("the refusal does not wrap ErrAnchorMismatch:\n%v", err)
	}
	if !strings.Contains(err.Error(), "does not end where its anchor says") {
		t.Errorf("the refusal does not say what it is:\n%v", err)
	}
	if report.State != AnchorMismatch {
		t.Errorf("a wholesale rewrite reported state %v, not AnchorMismatch", report.State)
	}
}

// A chain written before the anchor existed has no anchor file, and the check
// says nothing about it rather than failing every old record.
func TestA14_AChainWithoutAnAnchorIsNotAnError(t *testing.T) {
	root, id := t.TempDir(), "a14noanchor"
	if err := os.MkdirAll(filepath.Dir(Path(root, id)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(root, id), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := a14Anchor(t, root, id)
	if err != nil {
		t.Errorf("a missing anchor was reported as a failure: %v", err)
	}
	if report.State != AnchorMissing {
		t.Errorf("a missing anchor reported state %v, not AnchorMissing", report.State)
	}
}
