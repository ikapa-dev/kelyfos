package recorder

import (
	"bytes"
	"os"
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
