package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeSession(t *testing.T, root string) string {
	t.Helper()
	rec, err := Open(root, "test-sandbox")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	code := 0
	yes := true
	for _, e := range []Event{
		{Type: TypeSessionStart, Image: "base", Arch: "aarch64", Kelyfos: "test"},
		{Type: TypeCommandStart, Call: "c1", Cmd: []string{"/bin/sh", "-c", "echo hi"}, Via: "exec"},
		{Type: TypeCommandOutput, Call: "c1", Stream: "stdout", Data: "aGkK", Bytes: 3},
		{Type: TypeCommandExit, Call: "c1", Code: &code, DurationMS: 12},
		{Type: TypeEgressAttempt, Host: "api.github.com", Port: 443, Allowed: &yes, Mode: "terminated"},
		{Type: TypeSecretUse, Name: "GITHUB_TOKEN", Host: "api.github.com"},
		{Type: TypeSessionEnd, Reason: "shutdown", DurationMS: 1000},
	} {
		if err := rec.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Type, err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return Path(root, "test-sandbox")
}

func TestChainVerifies(t *testing.T) {
	path := writeSession(t, t.TempDir())
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := Verify(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("a freshly written session must verify: %v", err)
	}
	if n != 7 {
		t.Errorf("verified %d events, want 7", n)
	}
}

// The acceptance test for P2 says flipping one byte must make verification
// fail. This is that, exhaustively: every event in turn.
func TestFlippingOneByteBreaksTheChain(t *testing.T) {
	path := writeSession(t, t.TempDir())
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(blob), "\n"), "\n")

	for i := range lines {
		edited := append([]string(nil), lines...)
		// Change the recorded output of a command, the kind of edit someone
		// covering their tracks would make.
		edited[i] = strings.Replace(edited[i], `"source":"host"`, `"source":"guest"`, 1)
		if edited[i] == lines[i] {
			t.Fatalf("line %d was not modified by the test itself", i+1)
		}
		if _, _, err := Verify(strings.NewReader(strings.Join(edited, "\n"))); err == nil {
			t.Errorf("editing event %d went undetected", i+1)
		}
	}
}

func TestDeletingAnEventBreaksTheChain(t *testing.T) {
	path := writeSession(t, t.TempDir())
	blob, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(blob), "\n"), "\n")

	// Drop the egress event — precisely what someone hiding an exfiltration
	// attempt would remove.
	without := append(append([]string{}, lines[:4]...), lines[5:]...)
	if _, _, err := Verify(strings.NewReader(strings.Join(without, "\n"))); err == nil {
		t.Error("deleting an event went undetected")
	}
}

func TestReorderingBreaksTheChain(t *testing.T) {
	path := writeSession(t, t.TempDir())
	blob, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(blob), "\n"), "\n")
	lines[2], lines[3] = lines[3], lines[2]
	if _, _, err := Verify(strings.NewReader(strings.Join(lines, "\n"))); err == nil {
		t.Error("reordering events went undetected")
	}
}

// A session that is reopened must continue the existing chain rather than
// starting a new one, or the CLI being invoked twice would break its own log.
func TestReopenContinuesTheChain(t *testing.T) {
	root := t.TempDir()
	writeSession(t, root)

	rec, err := Open(root, "test-sandbox")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeCommandStart, Call: "c2", Cmd: []string{"true"}, Via: "exec"}); err != nil {
		t.Fatal(err)
	}
	rec.Close()

	blob, _ := os.ReadFile(filepath.Join(root, "sessions", "test-sandbox", "events.jsonl"))
	n, _, err := Verify(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("chain broken after reopening: %v", err)
	}
	if n != 8 {
		t.Errorf("verified %d events, want 8", n)
	}
}

// The head Verify returns is the digest of the last event it walked, and a
// chain that did not verify has no head at all.
//
// A reader quotes the head to say which record they hold — P6-6 prints it in the
// export and P6-7 signs it — so a head produced by anything other than a
// completed walk would be a number that survives the failure that should have
// killed it.
func TestTheHeadIsTheLastVerifiedEvent(t *testing.T) {
	path := writeSession(t, t.TempDir())
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	n, head, err := Verify(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("a freshly written session must verify: %v", err)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if want := events[len(events)-1].Hash; head != want {
		t.Errorf("head = %s, want the last event's digest %s", head, want)
	}
	if n != len(events) {
		t.Errorf("verified %d events, read %d", n, len(events))
	}

	// A break anywhere leaves no head to quote, including a break in the last
	// event — where the head would otherwise have been read off the line that
	// failed.
	lines := strings.Split(strings.TrimRight(string(blob), "\n"), "\n")
	for _, i := range []int{0, len(lines) - 1} {
		edited := append([]string(nil), lines...)
		edited[i] = strings.Replace(edited[i], `"source":"host"`, `"source":"guest"`, 1)
		if _, head, err := Verify(strings.NewReader(strings.Join(edited, "\n"))); err == nil {
			t.Errorf("editing event %d went undetected", i+1)
		} else if head != "" {
			t.Errorf("a broken chain returned head %q", head)
		}
	}

	// An empty file verifies vacuously and has nothing to quote.
	if n, head, err := Verify(strings.NewReader("")); err != nil || n != 0 || head != "" {
		t.Errorf("empty chain: %d events, head %q, err %v", n, head, err)
	}
}

// The cheapest forgery there is: a chain somebody typed, with no digests in it
// at all. It used to verify.
//
// The digest of a line whose hash is empty was defined as empty, and an empty
// digest matched an empty hash, so every line agreed with itself and the walk
// reported an intact chain. Nothing this product writes looks like that —
// Append always fills the field — so the only files it accepted were files
// nobody's recorder wrote. It stopped being theoretical with P6-6: before it,
// the thing being verified was a file this machine had written itself; after
// it, `kelyfos verify` runs over a file a stranger sent.
func TestAChainWithNoDigestsIsRefused(t *testing.T) {
	for _, name := range []string{"empty digests", "no hash field at all"} {
		var forged string
		switch name {
		case "empty digests":
			forged = `{"v":1,"seq":1,"ts":"2026-08-24T10:00:00.000Z","sandbox":"3f2a91c0","type":"session.start","source":"host","prev":"","hash":""}` + "\n" +
				`{"v":1,"seq":2,"ts":"2026-08-24T10:00:01.000Z","sandbox":"3f2a91c0","type":"session.end","source":"host","prev":"","hash":"","reason":"shutdown"}` + "\n"
		case "no hash field at all":
			forged = `{"seq":1,"type":"session.start"}` + "\n" + `{"seq":2,"type":"session.end"}` + "\n"
		}
		n, head, err := Verify(strings.NewReader(forged))
		if err == nil {
			t.Errorf("%s: a forged chain verified — %d events, head %q", name, n, head)
			continue
		}
		if !strings.Contains(err.Error(), "carries no digest") {
			t.Errorf("%s: refused for the wrong reason: %v", name, err)
		}
		if head != "" {
			t.Errorf("%s: a refused chain returned head %q", name, head)
		}
	}

	// And the refusal is about the missing digest, not about the line being
	// unusual: a real chain with its last digest blanked is refused the same
	// way, at the line that lost it.
	path := writeSession(t, t.TempDir())
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(blob), "\n"), "\n")
	var last Event
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatal(err)
	}
	lines[len(lines)-1] = strings.Replace(lines[len(lines)-1], `"hash":"`+last.Hash+`"`, `"hash":""`, 1)
	n, _, err := Verify(strings.NewReader(strings.Join(lines, "\n")))
	if err == nil || !strings.Contains(err.Error(), "carries no digest") {
		t.Errorf("blanking one digest was not caught: %d events, %v", n, err)
	}
}

// A secret's value must never reach the file, in any field or any form.
func TestSecretValuesAreNeverRecorded(t *testing.T) {
	root := t.TempDir()
	rec, _ := Open(root, "s")
	const value = "ghp_thisisaverysecrettokenvalue"
	if err := rec.Append(Event{Type: TypeSecretUse, Name: "GITHUB_TOKEN", Host: "api.github.com"}); err != nil {
		t.Fatal(err)
	}
	rec.Close()
	blob, _ := os.ReadFile(Path(root, "s"))
	if bytes.Contains(blob, []byte(value)) {
		t.Fatal("the flight recorder contains a secret value")
	}
	if !bytes.Contains(blob, []byte("GITHUB_TOKEN")) {
		t.Error("the secret's name should be recorded")
	}
}

// A session is written by several processes at once — `kelyfos run` holds the
// sandbox open while `kelyfos exec` and `kelyfos mcp` are separate invocations.
// Each holds its own Recorder on the same file, and if they do not coordinate
// they each keep a private sequence number and previous hash, interleave, and
// produce a log that can never verify. This reproduces exactly that shape.
func TestConcurrentWritersKeepOneChain(t *testing.T) {
	root := t.TempDir()

	const writers, each = 6, 25
	recs := make([]*Recorder, writers)
	for i := range recs {
		r, err := Open(root, "shared")
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		recs[i] = r
		defer r.Close()
	}

	var wg sync.WaitGroup
	for i, r := range recs {
		wg.Add(1)
		go func(i int, r *Recorder) {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if err := r.Append(Event{
					Type: TypeCommandStart,
					Call: fmt.Sprintf("w%d-%d", i, j),
					Cmd:  []string{"true"},
					Via:  "exec",
				}); err != nil {
					t.Errorf("writer %d append %d: %v", i, j, err)
					return
				}
			}
		}(i, r)
	}
	wg.Wait()

	blob, err := os.ReadFile(Path(root, "shared"))
	if err != nil {
		t.Fatal(err)
	}
	n, _, err := Verify(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("chain broken with %d concurrent writers: %v", writers, err)
	}
	if want := writers * each; n != want {
		t.Errorf("verified %d events, want %d — some appends were lost", n, want)
	}
}

// A chain written by a newer build still verifies here.
//
// This is the property docs/events.md §3 asserts — "adding a field is not
// breaking" — and it was false until P6-6. The digest used to be recomputed by
// re-marshalling the parsed struct, so a field this build does not know about
// was dropped before the re-hash and the chain came back as `event N has been
// modified`: tamper detection firing on a legitimate record, which is the
// loudest false alarm this product can produce. A reader who saw it would have
// had every reason to believe their audit trail had been edited.
//
// The fix recomputes from the bytes as written, so an unknown field survives
// into the preimage. The simulation is exact: the newer writer's digest is
// computed over its own line with the hash emptied in place, which is what
// Append does.
func TestAChainFromANewerBuildStillVerifies(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "newer")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(Event{Type: TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(Path(root, "newer"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(blob))

	var e Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}

	// What a build with one more tail field would have written.
	withField := strings.TrimSuffix(line, "}") + `,"a_field_this_build_does_not_know":"x"}`
	pre := strings.Replace(withField, `"hash":"`+e.Hash+`"`, `"hash":""`, 1)
	sum := sha256.Sum256([]byte(pre))
	newer := strings.Replace(withField, e.Hash, hex.EncodeToString(sum[:]), 1)

	n, _, err := Verify(strings.NewReader(newer + "\n"))
	if err != nil {
		t.Fatalf("a chain from a newer build was reported as tampered with: %v", err)
	}
	if n != 1 {
		t.Errorf("verified %d events, want 1", n)
	}
}

// F14 (2): blocked_packets round-trips through Append and Read like every
// other resource.summary field, and — like the rest of that event — is
// omitted entirely rather than written as an explicit zero when there was
// nothing to count, which is what every un-networked sandbox's receipt does.
func TestResourceSummaryCarriesBlockedPackets(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "test-sandbox")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := rec.Append(Event{Type: TypeResourceSummary, CPUSeconds: 1.5, BlockedPackets: 42}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := rec.Append(Event{Type: TypeResourceSummary, CPUSeconds: 1.5}); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	blob, err := os.ReadFile(Path(root, "test-sandbox"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("wrote 2 events, read back %d", len(events))
	}
	if events[0].BlockedPackets != 42 {
		t.Errorf("event 1: blocked_packets read back as %d, want 42", events[0].BlockedPackets)
	}
	if events[1].BlockedPackets != 0 {
		t.Errorf("event 2: blocked_packets read back as %d, want 0", events[1].BlockedPackets)
	}
	lines := strings.Split(strings.TrimSpace(string(blob)), "\n")
	if strings.Contains(lines[1], "blocked_packets") {
		t.Error("a sandbox that blocked nothing should omit blocked_packets, not write an explicit 0")
	}
}
