package recorder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// buildErasableChain writes a real chain through Append — not hand-rolled —
// with a session.start carrying Argv (the shape a real `kelyfos run --
// <command>` produces, per docs/retention.md §5), a command.output carrying
// Data, an mcp.host.call carrying Args, and a command.start carrying Cmd,
// followed by session.end so the erasure event lands somewhere realistic
// rather than at seq 1.
func buildErasableChain(t *testing.T, root, id string) (argv, data, args, cmd string) {
	t.Helper()
	rec, err := Open(root, id)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	argv = "jane's email is jane.doe@example.com"
	data = "the secret the guest printed: dummy-value-not-real"
	args = `{"path":"/etc/shadow"}`
	cmd = "curl https://api.example.com/users/john.doe@example.com"
	if err := rec.Append(Event{Type: TypeSessionStart, Argv: []string{"kelyfos", "run", "--", "claude", argv}}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeCommandOutput, Data: data, Bytes: len(data)}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeMCPHostCall, Call: "c1", Name: "sandbox_read_file", Args: args}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeCommandStart, Call: "c2", Cmd: []string{"curl", "https://api.example.com/users/john.doe@example.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	return argv, data, args, cmd
}

func TestEraseRedactsAndTheChainStillVerifies(t *testing.T) {
	root := t.TempDir()
	argv, data, args, cmdArg := buildErasableChain(t, root, "erase1")

	redacted, err := Erase(root, "erase1", "GDPR Article 17 request")
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if redacted != 4 {
		t.Fatalf("redacted = %d, want 4 (Argv, Data, Args, Cmd each on their own event)", redacted)
	}

	blob, err := os.ReadFile(Path(root, "erase1"))
	if err != nil {
		t.Fatal(err)
	}

	// The values themselves must be unrecoverable from the raw file — the
	// same check the record's own secret-value acceptance test already
	// makes, applied here to erased content instead. Proven live in
	// practice too: an early version of docs/cookbook.md's recipe 15 put
	// its own target value only in Argv (via `kelyfos run -- claude
	// "..."`) and a version of Erase that redacted only Data/Args/Cmd left
	// it recoverable — this is that finding kept as a regression test.
	for _, want := range []string{argv, data, args, cmdArg} {
		if strings.Contains(string(blob), want) {
			t.Fatalf("raw file still contains erased content %q", want)
		}
	}

	// session.start, command.output, mcp.host.call, command.start,
	// session.end, plus the appended session.erasure — six events, the
	// original five untouched in count and order.
	n, head, verr := Verify(bytes.NewReader(blob))
	if verr != nil {
		t.Fatalf("erased chain does not verify: %v", verr)
	}
	if n != 6 {
		t.Fatalf("Verify counted %d events, want 6", n)
	}
	if head == "" {
		t.Fatal("Verify returned no chain head")
	}

	events, rerr := Read(bytes.NewReader(blob))
	if rerr != nil {
		t.Fatalf("reading back the erased chain: %v", rerr)
	}
	if len(events) != 6 {
		t.Fatalf("want 6 events (5 original + 1 erasure), got %d", len(events))
	}
	last := events[len(events)-1]
	if last.Type != TypeSessionErasure {
		t.Fatalf("last event is %q, want %q", last.Type, TypeSessionErasure)
	}
	if last.Reason != "GDPR Article 17 request" {
		t.Errorf("erasure event Reason = %q", last.Reason)
	}
	if last.Modified != 4 {
		t.Errorf("erasure event Modified = %d, want 4", last.Modified)
	}
	if last.Seq != 6 {
		t.Errorf("erasure event Seq = %d, want 6 (appended, not inserted)", last.Seq)
	}

	// Fingerprints present where the content used to be.
	if len(events[0].Argv) != 1 || !strings.Contains(events[0].Argv[0], "erased") {
		t.Errorf("Argv not redacted with a fingerprint: %v", events[0].Argv)
	}
	if !strings.Contains(events[1].Data, "erased") || !strings.Contains(events[1].Data, "sha256:") {
		t.Errorf("Data not redacted with a fingerprint: %q", events[1].Data)
	}
	if !strings.Contains(events[2].Args, "erased") || !strings.Contains(events[2].Args, "sha256:") {
		t.Errorf("Args not redacted with a fingerprint: %q", events[2].Args)
	}
	if len(events[3].Cmd) != 1 || !strings.Contains(events[3].Cmd[0], "erased") {
		t.Errorf("Cmd not redacted with a fingerprint: %v", events[3].Cmd)
	}

	// Everything Erase does not touch survives unchanged.
	if events[0].Type != TypeSessionStart {
		t.Errorf("session.start's own type changed: %+v", events[0])
	}
	if events[4].Type != TypeSessionEnd || events[4].Reason != "shutdown" {
		t.Errorf("session.end's own untouched fields changed: %+v", events[4])
	}
}

func TestEraseRefusesAChainThatDoesNotVerify(t *testing.T) {
	root := t.TempDir()
	buildErasableChain(t, root, "erase2")

	path := Path(root, "erase2")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one byte in the middle of the file — the same tamper
	// TestFlippingOneByteBreaksTheChain already proves Verify catches.
	tampered := []byte(string(blob))
	for i, b := range tampered {
		if b == 'd' {
			tampered[i] = 'x'
			break
		}
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Erase(root, "erase2", "test"); err == nil {
		t.Fatal("Erase accepted a chain that does not verify")
	}
}

func TestEraseRefusesAnEmptyChain(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "erase3")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Erase(root, "erase3", "test"); err == nil {
		t.Fatal("Erase accepted an empty chain")
	}
}

func TestEraseRefusesWhenNothingToRedact(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "erase4")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Erase(root, "erase4", "test"); err == nil {
		t.Fatal("Erase accepted a chain with no redactable field")
	}
}

// TestEraseCascadesTheHashForward is the property that makes "preserving
// chain integrity" true rather than assumed: redacting an EARLY event must
// change the digest of every LATER one too, since each event's Hash covers
// Prev and Prev is the previous event's Hash. Proven by comparing the
// post-erasure hash of the untouched session.end event against what it was
// before erasure — it must differ, and the chain must still verify with the
// new value.
func TestEraseCascadesTheHashForward(t *testing.T) {
	root := t.TempDir()
	buildErasableChain(t, root, "erase5")

	before, err := Read(bytes.NewReader(readFile(t, Path(root, "erase5"))))
	if err != nil {
		t.Fatal(err)
	}
	endHashBefore := before[len(before)-1].Hash

	if _, err := Erase(root, "erase5", "test"); err != nil {
		t.Fatalf("Erase: %v", err)
	}

	after, err := Read(bytes.NewReader(readFile(t, Path(root, "erase5"))))
	if err != nil {
		t.Fatal(err)
	}
	// session.end is now at the same seq (5) as before, still the second-to-
	// last event once the erasure event is appended after it.
	var endAfter Event
	for _, e := range after {
		if e.Type == TypeSessionEnd {
			endAfter = e
		}
	}
	if endAfter.Hash == "" {
		t.Fatal("could not find session.end in the erased chain")
	}
	if endAfter.Hash == endHashBefore {
		t.Fatal("session.end's own hash did not change after an earlier event was redacted — " +
			"the chain was not actually rehashed forward, so a reader comparing this event's " +
			"hash against a pre-erasure record would see a false match")
	}
	if _, _, err := Verify(bytes.NewReader(readFile(t, Path(root, "erase5")))); err != nil {
		t.Fatalf("chain does not verify after erasure: %v", err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEraseDoesNotLoseEventsFromAConcurrentWriter is B1's core property,
// proven directly rather than only through the guard that now makes the
// scenario hard to reach via the CLI: a Recorder that already has this
// session's chain open across an Erase must not lose whatever it appends
// afterward. The reviewer reproduced silent loss on real, running code —
// erase a chain a writer still held open, the writer's next events never
// reached disk, and kelyfos verify reported the truncated chain as clean.
// This keeps rec's own *os.File open across Erase, the same shape a
// Recorder inside a long-running process has, and checks that its next
// Append lands in the rewritten chain rather than an inode nothing can
// read back.
func TestEraseDoesNotLoseEventsFromAConcurrentWriter(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "live-writer")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := rec.Append(Event{Type: TypeSessionStart, Argv: []string{"kelyfos", "run"}}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeCommandOutput, Data: "before the erase"}); err != nil {
		t.Fatal(err)
	}
	// session.end so Erase's own guard (B1's other half) does not refuse
	// this chain outright — this test is about the writer that is still
	// there afterward, not about reopening that separate question. rec
	// itself is deliberately NOT closed: it is exactly the shape of a
	// Recorder a long-running process keeps open across its own session.
	if err := rec.Append(Event{Type: TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}

	redacted, err := Erase(root, "live-writer", "test, with a writer still holding the file open")
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if redacted == 0 {
		t.Fatal("Erase redacted nothing — this test needs it to have actually rewritten the chain")
	}

	// The writer's next three events — the shape the reviewer's own repro
	// used — appended through the SAME Recorder object that was open
	// before, during and after the erase.
	for i := 0; i < 3; i++ {
		if err := rec.Append(Event{Type: TypeCommandOutput, Data: fmt.Sprintf("after the erase, event %d", i)}); err != nil {
			t.Fatalf("Append after Erase (event %d): %v", i, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	blob, err := os.ReadFile(Path(root, "live-writer"))
	if err != nil {
		t.Fatal(err)
	}
	n, _, verr := Verify(bytes.NewReader(blob))
	if verr != nil {
		t.Fatalf("chain does not verify after a writer appended post-erase: %v", verr)
	}
	// session.start, command.output, session.end, session.erasure, then the
	// three events appended after — seven in total. Any fewer means one of
	// the writer's three post-erase events was lost the way B1 describes.
	if n != 7 {
		t.Fatalf("Verify counted %d events, want 7 (4 pre-erase + 3 appended by the still-open writer) — "+
			"a count under 7 is exactly B1's silent loss", n)
	}
	events, rerr := Read(bytes.NewReader(blob))
	if rerr != nil {
		t.Fatal(rerr)
	}
	for i := 0; i < 3; i++ {
		got := events[4+i]
		want := fmt.Sprintf("after the erase, event %d", i)
		if got.Data != want {
			t.Fatalf("event %d after the erase = %q, want %q — the writer's own event landed on the wrong slot or was lost", i, got.Data, want)
		}
	}
}

// TestEraseRefusesAChainWithNoSessionEnd is B1's second half: the guard
// that used to be hasLiveRunDir alone (host/sessions.go) resolves
// sandbox.RunDirOf(id), which only exists for an ordinary sandbox whose
// own id names its run directory — a team's chain and a `kelyfos
// serve-mcp` process's own audit chain are both opened under an id
// sandbox.NewID() mints that is never any sandbox's own id, so no run
// directory is ever named for either one, and the guard alone cannot see
// that either is still live. Erase itself now refuses any chain with no
// session.end anywhere in it, which covers both: a running team has not
// written one yet, and neither has a running serve-mcp process's own
// session.
func TestEraseRefusesAChainWithNoSessionEnd(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "still-open")
	if err != nil {
		t.Fatal(err)
	}
	// The shape of a live team or serve-mcp chain: opened, something
	// written, never closed.
	if err := rec.Append(Event{Type: TypeSessionStart, Reason: ReasonServeMCP}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeCommandOutput, Data: "still running"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Erase(root, "still-open", "test"); err == nil {
		t.Fatal("Erase accepted a chain with no session.end anywhere in it")
	} else if !strings.Contains(err.Error(), "session.end") {
		t.Errorf("refusal does not mention session.end, which is why this was refused: %v", err)
	}
}

// TestEraseTwiceRefusesTheSecondRun is B2's direct repro: redactString and
// redactStrings used to hash whatever was CURRENTLY in a field, which on a
// second pass is the placeholder from the first — so running erase twice
// silently replaced every real fingerprint with the hash of the note text
// "(erased — sha256:...)" and reported a nonzero redacted count for a
// chain that had nothing left to redact. The reviewer reproduced this
// through the real CLI; this is the same property proven directly against
// Erase.
func TestEraseTwiceRefusesTheSecondRun(t *testing.T) {
	root := t.TempDir()
	buildErasableChain(t, root, "erase-twice")

	first, err := Erase(root, "erase-twice", "first pass")
	if err != nil {
		t.Fatalf("first Erase: %v", err)
	}
	if first == 0 {
		t.Fatal("first Erase redacted nothing")
	}
	fingerprintsAfterFirst, err := Read(bytes.NewReader(readFile(t, Path(root, "erase-twice"))))
	if err != nil {
		t.Fatal(err)
	}

	second, err := Erase(root, "erase-twice", "second pass")
	if err == nil {
		t.Fatalf("a second Erase on an already-erased chain succeeded (redacted %d) — it must refuse, "+
			"not re-hash a placeholder and destroy the real fingerprint", second)
	}
	if !strings.Contains(err.Error(), "nothing to erase") {
		t.Errorf("refusal = %v, want it to say there is nothing left to erase", err)
	}

	// The fingerprints from the first pass must be untouched — this is what
	// "refuses" has to mean here, not merely "returns an error while still
	// mutating the file."
	fingerprintsAfterSecond, err := Read(bytes.NewReader(readFile(t, Path(root, "erase-twice"))))
	if err != nil {
		t.Fatal(err)
	}
	for i := range fingerprintsAfterFirst {
		if fingerprintsAfterFirst[i].Data != fingerprintsAfterSecond[i].Data ||
			(len(fingerprintsAfterFirst[i].Argv) > 0 &&
				fingerprintsAfterFirst[i].Argv[0] != fingerprintsAfterSecond[i].Argv[0]) {
			t.Fatalf("event %d's fingerprint changed after a refused second Erase — the real digest from the first pass was lost", i)
		}
	}
}

// TestEraseStampsVAndTS is B4's direct repro: Erase builds its own
// session.erasure event as a struct literal and rehashes it directly,
// bypassing Append — the only place that otherwise stamps V and TS — so a
// real erased chain carried a session.erasure event with v:0 and ts:"",
// the one event on the chain whose entire purpose is accountability
// failing the invariant docs/events.md states for every event.
func TestEraseStampsVAndTS(t *testing.T) {
	root := t.TempDir()
	buildErasableChain(t, root, "erase-stamps")
	if _, err := Erase(root, "erase-stamps", "test"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	events, err := Read(bytes.NewReader(readFile(t, Path(root, "erase-stamps"))))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.V != Version {
			t.Errorf("event %d (%s): v = %d, want %d", e.Seq, e.Type, e.V, Version)
		}
		if e.TS == "" {
			t.Errorf("event %d (%s): ts is empty", e.Seq, e.Type)
		}
	}
	last := events[len(events)-1]
	if last.Type != TypeSessionErasure {
		t.Fatalf("last event is %q, want %q", last.Type, TypeSessionErasure)
	}
}

// TestEraseAnchorsThePreErasureHead is S1: session.erasure's own SHA256
// carries the chain head immediately before the rewrite began — the value
// Verify would have returned had it been asked right before Erase ran —
// so a reader holding an earlier export of the same chain can prove the
// erased chain is the honest successor of exactly the chain they hold,
// rather than trusting the erasure by convention. Without this anchor a
// hand-edited chain, rehashed from event 1 with no erasure event at all,
// verifies identically to a real erasure — proven directly below.
func TestEraseAnchorsThePreErasureHead(t *testing.T) {
	root := t.TempDir()
	buildErasableChain(t, root, "erase-anchor")

	preBlob := readFile(t, Path(root, "erase-anchor"))
	_, preHead, err := Verify(bytes.NewReader(preBlob))
	if err != nil {
		t.Fatalf("pre-erasure chain does not verify: %v", err)
	}
	if preHead == "" {
		t.Fatal("pre-erasure chain has no head")
	}

	if _, err := Erase(root, "erase-anchor", "test"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	events, err := Read(bytes.NewReader(readFile(t, Path(root, "erase-anchor"))))
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Type != TypeSessionErasure {
		t.Fatalf("last event is %q, want %q", last.Type, TypeSessionErasure)
	}
	if last.SHA256 != preHead {
		t.Fatalf("session.erasure SHA256 = %q, want the pre-erasure chain head %q", last.SHA256, preHead)
	}

	// The property this anchor exists to make provable: a chain honestly
	// erased from the one a reader already holds carries that reader's own
	// head as the erasure event's SHA256. A chain forged instead — hand-
	// edited and rehashed from event 1 with no erasure event recorded at
	// all — verifies exactly as cleanly and gives no such anchor to check.
	forged := bytes.Replace(preBlob, []byte("the secret the guest printed: dummy-value-not-real"),
		[]byte("the secret the guest printed: something else entirely!!!!!!!!!!!"), 1)
	forged, err = rehashFromScratch(forged)
	if err != nil {
		t.Fatalf("building the forged chain: %v", err)
	}
	if _, _, err := Verify(bytes.NewReader(forged)); err != nil {
		t.Fatalf("the forged chain does not even verify, which is not this test's point: %v", err)
	}
	forgedEvents, err := Read(bytes.NewReader(forged))
	if err != nil {
		t.Fatal(err)
	}
	if forgedEvents[len(forgedEvents)-1].Type == TypeSessionErasure {
		t.Fatal("the forged chain unexpectedly carries a session.erasure event")
	}
}

// rehashFromScratch re-chains a set of events from event 1, the way a
// forger covering their tracks would — and the way this project's own
// Erase used to, before S1 added the pre-erasure head anchor. It exists
// only for TestEraseAnchorsThePreErasureHead, to build the "verifies but
// is not an honest erasure" chain that test compares against.
func rehashFromScratch(blob []byte) ([]byte, error) {
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		return nil, err
	}
	prev := ""
	for i := range events {
		events[i].Seq = i + 1
		events[i].Prev = prev
		events[i].Hash = ""
		digest, err := hashOf(events[i])
		if err != nil {
			return nil, err
		}
		events[i].Hash = digest
		prev = digest
	}
	var buf bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// eraseCoverageMarker is a distinguishing value TestEraseCoversEveryContentField
// puts in one field at a time. It is deliberately shaped like real guest
// content (an email address) rather than an opaque token, so a field that
// leaks it reads as the same kind of finding the adversarial review made.
const eraseCoverageMarker = "MARKER-jane.doe@example.com-content-fixture"

// writeRawChain writes events directly to id's own chain file, computing
// Seq, Prev and Hash itself the way Append does — but leaving every OTHER
// field exactly as the caller set it. Going through Open/Append instead
// would not do that: Append unconditionally overwrites V, TS, Sandbox,
// Prev and Hash on every event regardless of what the caller supplies
// (recorder.go's own Append), so a marker checkEraseField plants in one of
// those fields would be silently discarded before it ever reached disk —
// testing Append's own stamping behaviour by accident rather than Erase's
// redaction of a field that happens to share a name with one Append
// manages. Bypassing Append is what makes TS and Sandbox's own exemptions
// genuinely checkable.
func writeRawChain(t *testing.T, root, id string, events []Event) {
	t.Helper()
	prev := ""
	for i := range events {
		events[i].Seq = i + 1
		events[i].Prev = prev
		events[i].Hash = ""
		digest, err := hashOf(events[i])
		if err != nil {
			t.Fatal(err)
		}
		events[i].Hash = digest
		prev = digest
	}
	var buf bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	path := Path(root, id)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// checkEraseField is TestEraseCoversEveryContentField's per-field check: it
// builds a chain with the marker in exactly the field `set` places it, runs
// Erase, and confirms the outcome matches eraseExempt's own verdict for
// that field name. A field NOT in eraseExempt must have its marker
// scrubbed from the raw file; a field IN eraseExempt must keep it (or, if
// the marker was the only redactable content, Erase must give the
// documented "nothing to erase" refusal, which is consistent with the
// field being exempt rather than a failure of this check).
//
// Hash and Prev are skipped rather than tested this way: Erase's own final
// rehash pass recomputes both, unconditionally, for every event, whatever
// redactEventFields did to them in between — so a chain that verifies
// (which Erase requires before it will touch anything) can never carry a
// marker in either field to begin with, and there is nothing this check
// could observe either way.
func checkEraseField(t *testing.T, name string, set func(e *Event, marker string)) {
	t.Helper()
	if name == "Hash" || name == "Prev" {
		t.Skip("Hash and Prev are recomputed unconditionally by Erase's own final rehash pass; " +
			"a chain that verifies can never carry a marker in either to begin with")
	}
	root := t.TempDir()
	e := Event{Type: TypeCommandExit, V: Version, TS: "2026-01-01T00:00:00.000Z", Sandbox: "coverage"}
	set(&e, eraseCoverageMarker)
	writeRawChain(t, root, "coverage", []Event{e, {Type: TypeSessionEnd, Reason: "shutdown"}})

	reason, exempt := eraseExempt[name]
	redacted, eraseErr := Erase(root, "coverage", "coverage test")

	if exempt {
		if eraseErr != nil {
			if strings.Contains(eraseErr.Error(), "nothing to erase") {
				return // consistent: the only redactable field was exempt
			}
			t.Fatalf("field %s is exempt (%s) but Erase refused for an unrelated reason: %v", name, reason, eraseErr)
		}
		blob := readFile(t, Path(root, "coverage"))
		if !bytes.Contains(blob, []byte(eraseCoverageMarker)) {
			t.Fatalf("field %s is in eraseExempt (%q) but Erase redacted it anyway — "+
				"update eraseExempt or redactEventFields so they agree", name, reason)
		}
		return
	}

	if eraseErr != nil {
		t.Fatalf("field %s is NOT in eraseExempt but Erase refused to redact it: %v", name, eraseErr)
	}
	if redacted == 0 {
		t.Fatalf("field %s's content is gone but Erase reported 0 events redacted", name)
	}
	blob := readFile(t, Path(root, "coverage"))
	if bytes.Contains(blob, []byte(eraseCoverageMarker)) {
		t.Fatalf("field %s is not in eraseExempt and Erase left its content in the raw file — "+
			"either redact it in redactEventFields or add it to eraseExempt with a stated reason", name)
	}
}

// TestEraseCoversEveryContentField is B3 closed structurally rather than by
// list, the same way TestClipToBudgetCoversEverySliceField
// (fuzz_test.go) already closes the identical failure class for
// clipToBudget. It walks Event by reflection — every string field,
// every []string field, *EvError's two, and the three struct slices' own
// fields — puts eraseCoverageMarker in exactly one at a time, runs Erase,
// and asserts the outcome against eraseExempt: exempt means the marker
// must survive, not-exempt means it must not. A field that is neither
// redacted nor named in eraseExempt fails here with the field's own name,
// which is what an adversarial review otherwise has to find by hand — this
// review found Cwd, Path, Peer, Comm, Workspace, Host, Name, Allow, Agents,
// Edges and StoreKeys surviving fully intact, and every one of them is
// covered by this test now.
func TestEraseCoversEveryContentField(t *testing.T) {
	et := reflect.TypeOf(Event{})
	for i := 0; i < et.NumField(); i++ {
		field := et.Field(i)
		idx := i

		switch {
		case field.Type.Kind() == reflect.String:
			t.Run(field.Name, func(t *testing.T) {
				checkEraseField(t, field.Name, func(e *Event, marker string) {
					reflect.ValueOf(e).Elem().Field(idx).SetString(marker)
				})
			})

		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.String:
			t.Run(field.Name, func(t *testing.T) {
				checkEraseField(t, field.Name, func(e *Event, marker string) {
					reflect.ValueOf(e).Elem().Field(idx).Set(reflect.ValueOf([]string{marker}))
				})
			})

		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Struct:
			elemType := field.Type.Elem()
			for j := 0; j < elemType.NumField(); j++ {
				inner := elemType.Field(j)
				name := field.Name + "." + inner.Name
				innerIdx := j
				switch inner.Type.Kind() {
				case reflect.String:
					t.Run(name, func(t *testing.T) {
						checkEraseField(t, name, func(e *Event, marker string) {
							elem := reflect.New(elemType).Elem()
							elem.Field(innerIdx).SetString(marker)
							slice := reflect.MakeSlice(field.Type, 1, 1)
							slice.Index(0).Set(elem)
							reflect.ValueOf(e).Elem().Field(idx).Set(slice)
						})
					})
				case reflect.Slice:
					if inner.Type.Elem().Kind() != reflect.String {
						t.Fatalf("field %s is a slice of %s — extend this test before it can cover that shape",
							name, inner.Type.Elem().Kind())
					}
					t.Run(name, func(t *testing.T) {
						checkEraseField(t, name, func(e *Event, marker string) {
							elem := reflect.New(elemType).Elem()
							elem.Field(innerIdx).Set(reflect.ValueOf([]string{marker}))
							slice := reflect.MakeSlice(field.Type, 1, 1)
							slice.Index(0).Set(elem)
							reflect.ValueOf(e).Elem().Field(idx).Set(slice)
						})
					})
				default:
					t.Fatalf("field %s has kind %s — extend this test before it can cover that shape",
						name, inner.Type.Kind())
				}
			}

		case field.Type.Kind() == reflect.Ptr && field.Type.Elem().Kind() == reflect.Struct:
			elemType := field.Type.Elem()
			for j := 0; j < elemType.NumField(); j++ {
				inner := elemType.Field(j)
				if inner.Type.Kind() != reflect.String {
					continue
				}
				name := field.Name + "." + inner.Name
				innerIdx := j
				t.Run(name, func(t *testing.T) {
					checkEraseField(t, name, func(e *Event, marker string) {
						ptr := reflect.ValueOf(e).Elem().Field(idx)
						ptr.Set(reflect.New(elemType))
						ptr.Elem().Field(innerIdx).SetString(marker)
					})
				})
			}
		}
	}
}
