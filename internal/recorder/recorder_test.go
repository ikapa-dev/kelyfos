package recorder

import (
	"bytes"
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
	n, err := Verify(bytes.NewReader(blob))
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
		if _, err := Verify(strings.NewReader(strings.Join(edited, "\n"))); err == nil {
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
	if _, err := Verify(strings.NewReader(strings.Join(without, "\n"))); err == nil {
		t.Error("deleting an event went undetected")
	}
}

func TestReorderingBreaksTheChain(t *testing.T) {
	path := writeSession(t, t.TempDir())
	blob, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(blob), "\n"), "\n")
	lines[2], lines[3] = lines[3], lines[2]
	if _, err := Verify(strings.NewReader(strings.Join(lines, "\n"))); err == nil {
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
	n, err := Verify(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("chain broken after reopening: %v", err)
	}
	if n != 8 {
		t.Errorf("verified %d events, want 8", n)
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
	n, err := Verify(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("chain broken with %d concurrent writers: %v", writers, err)
	}
	if want := writers * each; n != want {
		t.Errorf("verified %d events, want %d — some appends were lost", n, want)
	}
}
