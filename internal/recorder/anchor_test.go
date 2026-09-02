package recorder

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The adversarial review of 2026-09-01's recorder findings, in the order the
// report raised them. The old CheckHead read the chain and its anchor unlocked
// and in two steps, then retried after 50ms; ReadSnapshot reads both under one
// shared lock, and CheckAnchor distinguishes a match, an interrupted append,
// a missing or unreadable anchor, and a genuine rewrite.

// H6: a verify that runs while a writer is flat-out appending must see one
// consistent chain-and-anchor pair every time, not the benign line-ahead-of-
// anchor ordering the old unlocked read could catch mid-append and call
// tampering. Fifty verifies under a writer doing nothing but append: every one
// AnchorMatches.
func TestReview_VerifyUnderALiveWriterSeesOneConsistentPair(t *testing.T) {
	root, id := t.TempDir(), "h6"
	w, err := Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Seed one event so the chain is non-empty from the first verify.
	if err := w.Append(Event{Type: TypeSessionStart, Reason: "h6"}); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := w.Append(Event{Type: TypeCommandOutput, Stream: "stdout", Data: "x"}); err != nil {
				return
			}
		}
	}()

	for i := 0; i < 50; i++ {
		report, err := a14Anchor(t, root, id)
		if err != nil {
			close(stop)
			<-done
			t.Fatalf("verify %d under a live writer false-alarmed: %v", i, err)
		}
		if report.State != AnchorMatches {
			close(stop)
			<-done
			t.Fatalf("verify %d saw %v, not a matching anchor — the reader caught a torn chain/anchor pair", i, report)
		}
	}
	close(stop)
	<-done
}

// H7: a crash between an append's line write and its anchor rename leaves the
// chain one ahead of an honest anchor. That is an interrupted append, an
// observation — not the permanent false tamper verdict the old behind-by-one-
// blind check produced.
func TestReview_AnAnchorOneBehindWithTheRightDigestIsAnObservation(t *testing.T) {
	root, id := t.TempDir(), "h7"
	r := a14Recorder(t, root, id)
	for i := 0; i < 3; i++ {
		if err := r.Append(Event{Type: TypeSessionStart, Reason: "h7"}); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()

	blob, err := os.ReadFile(Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	// Rewind the anchor to where it stood before the last append's line landed:
	// one event back, at the previous head — which is exactly the last event's
	// own prev. This is the state a SIGKILL between Write(line) and the anchor
	// rename leaves behind.
	dir := filepath.Dir(Path(root, id))
	if err := writeHeadFile(dir, headDoc{Sandbox: id, Seq: last.Seq - 1, Hash: last.Prev}); err != nil {
		t.Fatal(err)
	}

	report, err := a14Anchor(t, root, id)
	if err != nil {
		t.Fatalf("a one-behind anchor with the right digest was called tampering: %v", err)
	}
	if report.State != AnchorBehindByOne {
		t.Fatalf("an interrupted append reported %v, not AnchorBehindByOne", report)
	}
	// The distinction is real: an anchor one behind but with the WRONG digest
	// is a rewrite, not an interrupted append, and must be caught.
	if err := writeHeadFile(dir, headDoc{Sandbox: id, Seq: last.Seq - 1, Hash: "deadbeef"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a14Anchor(t, root, id); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("a one-behind anchor with the wrong digest was not caught as a mismatch: %v", err)
	}
}

// M9a: deleting or corrupting the anchor was the same-uid attacker's cheapest
// move, and the old check said nothing — ENOENT returned nil and --verify never
// reported whether an anchor was even consulted. Now a missing anchor is
// AnchorMissing and a corrupt one AnchorUnreadable, each a surfaced state
// rather than silence.
func TestReview_AMissingOrCorruptAnchorIsReportedNotSilent(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		root, id := t.TempDir(), "m9a-missing"
		r := a14Recorder(t, root, id)
		if err := r.Append(Event{Type: TypeSessionStart, Reason: "m9a"}); err != nil {
			t.Fatal(err)
		}
		r.Close()
		if err := os.Remove(HeadPath(root, id)); err != nil {
			t.Fatal(err)
		}
		report, err := a14Anchor(t, root, id)
		if err != nil {
			t.Fatalf("a deleted anchor was reported as a failure: %v", err)
		}
		if report.State != AnchorMissing {
			t.Fatalf("a deleted anchor reported %v, not AnchorMissing", report)
		}
	})
	t.Run("corrupt", func(t *testing.T) {
		root, id := t.TempDir(), "m9a-corrupt"
		r := a14Recorder(t, root, id)
		if err := r.Append(Event{Type: TypeSessionStart, Reason: "m9a"}); err != nil {
			t.Fatal(err)
		}
		r.Close()
		if err := os.WriteFile(HeadPath(root, id), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		report, err := a14Anchor(t, root, id)
		if err != nil {
			t.Fatalf("a corrupt anchor was reported as a failure: %v", err)
		}
		if report.State != AnchorUnreadable {
			t.Fatalf("a corrupt anchor reported %v, not AnchorUnreadable", report)
		}
	})
}

// M9b (refuse): erase laundered a mismatch — it verified the chain but not the
// anchor before rewriting, then wrote a fresh anchor, so a chain-versus-anchor
// disagreement came out the other side as a matching pair. Erase now refuses a
// chain whose anchor genuinely disagrees.
func TestReview_EraseRefusesAChainWhoseAnchorDisagrees(t *testing.T) {
	root, id := t.TempDir(), "m9b-refuse"
	writeErasableChain(t, root, id)

	// Corrupt the anchor into a genuine disagreement (an end the chain does not
	// have, and not one behind it either).
	dir := filepath.Dir(Path(root, id))
	if err := writeHeadFile(dir, headDoc{Sandbox: id, Seq: 999, Hash: "deadbeef"}); err != nil {
		t.Fatal(err)
	}

	_, err := Erase(root, id, "gdpr")
	if err == nil {
		t.Fatal("erase ran over a chain whose anchor disagrees, laundering the mismatch")
	}
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("the refusal does not wrap ErrAnchorMismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "signed export") {
		t.Errorf("the refusal does not point at the record to keep: %v", err)
	}
}

// M9b (proceed): a missing anchor and an anchor one behind an interrupted
// append are not disagreements — erase proceeds over both and writes the anchor
// the rewritten chain proves.
func TestReview_EraseProceedsOverAMissingOrOneBehindAnchor(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		root, id := t.TempDir(), "m9b-missing"
		writeErasableChain(t, root, id)
		if err := os.Remove(HeadPath(root, id)); err != nil {
			t.Fatal(err)
		}
		if _, err := Erase(root, id, "gdpr"); err != nil {
			t.Fatalf("erase refused a chain with no anchor: %v", err)
		}
		assertAnchorMatchesAfterErase(t, root, id)
	})
	t.Run("one-behind", func(t *testing.T) {
		root, id := t.TempDir(), "m9b-behind"
		writeErasableChain(t, root, id)
		blob, err := os.ReadFile(Path(root, id))
		if err != nil {
			t.Fatal(err)
		}
		events, err := Read(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		last := events[len(events)-1]
		dir := filepath.Dir(Path(root, id))
		if err := writeHeadFile(dir, headDoc{Sandbox: id, Seq: last.Seq - 1, Hash: last.Prev}); err != nil {
			t.Fatal(err)
		}
		if _, err := Erase(root, id, "gdpr"); err != nil {
			t.Fatalf("erase refused a chain whose anchor was one behind: %v", err)
		}
		assertAnchorMatchesAfterErase(t, root, id)
	})
}

// L9: a failed anchor rename must leave no temp file behind and say so exactly
// once, not once per append.
func TestReview_AFailedAnchorWriteLeavesNoTempFileAndSaysSoOnce(t *testing.T) {
	root, id := t.TempDir(), "l9"
	r, err := Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	dir := filepath.Dir(Path(root, id))
	// Take the anchor path with a NON-EMPTY directory, so every rename onto it
	// fails persistently — the shape L9 describes. Non-empty matters: an empty
	// directory would be removed by appendLocked's own cleanup, and the next
	// rename would then succeed, so the failure would not persist across the
	// five appends this test needs it to.
	if err := os.Mkdir(HeadFile(dir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(HeadFile(dir), "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldStderr := os.Stderr
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = pw

	for i := 0; i < 5; i++ {
		if err := r.Append(Event{Type: TypeCommandOutput, Stream: "stdout", Data: "x"}); err != nil {
			os.Stderr = oldStderr
			t.Fatalf("append %d failed on an anchor-write failure that should not fail the append: %v", i, err)
		}
	}
	pw.Close()
	os.Stderr = oldStderr
	out, _ := io.ReadAll(pr)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "head.json.tmp-") {
			t.Errorf("a failed anchor rename left a temp file behind: %s", e.Name())
		}
	}
	if n := strings.Count(string(out), "the chain anchor could not be updated"); n != 1 {
		t.Errorf("the anchor-write warning was printed %d times across five appends, want exactly 1:\n%s", n, out)
	}
}

// BenchmarkAppend measures the single-writer append cost the review put a number
// on: an anchor write (CreateTemp+Write+Close+Rename) now rides on every append.
func BenchmarkAppend(b *testing.B) {
	root, id := b.TempDir(), "bench"
	r, err := Open(root, id)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := r.Append(Event{Type: TypeCommandOutput, Stream: "stdout", Data: "x"}); err != nil {
			b.Fatal(err)
		}
	}
}

// writeErasableChain builds a chain erase will actually rewrite: a session with
// a redactable field (a file.write path) and a session.end, closed, its anchor
// matching. Everything but the anchor is already valid, so a test that then
// perturbs only the anchor isolates the anchor behaviour.
func writeErasableChain(t *testing.T, root, id string) {
	t.Helper()
	r := a14Recorder(t, root, id)
	if err := r.Append(Event{Type: TypeSessionStart, Reason: "erasable"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Append(Event{Type: TypeFileWrite, Path: "/work/secret.txt", SHA256: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Append(Event{Type: TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	// Confirm the precondition: chain and anchor agree before the test perturbs
	// one of them.
	report, err := a14Anchor(t, root, id)
	if err != nil || report.State != AnchorMatches {
		t.Fatalf("the erasable chain did not start with a matching anchor: %v / %v", report, err)
	}
}

// assertAnchorMatchesAfterErase confirms an erase that proceeded left the chain
// verifying and its freshly written anchor matching it.
func assertAnchorMatchesAfterErase(t *testing.T, root, id string) {
	t.Helper()
	report, err := a14Anchor(t, root, id)
	if err != nil {
		t.Fatalf("after erase the chain and anchor disagree: %v", err)
	}
	if report.State != AnchorMatches {
		t.Fatalf("after erase the anchor did not match the rewritten chain: %v", report)
	}
}
