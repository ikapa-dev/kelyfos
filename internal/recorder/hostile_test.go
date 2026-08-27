package recorder

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
)

// The hostile corpus for the flight recorder's own writer (S1).
//
// Append had no size guard of its own: it marshalled and wrote whatever Event
// it was handed. Two independent, unprivileged doors used to reach it with a
// single field big enough to write a line no reader's bufio.Scanner (capped at
// MaxLine) could read back — internal/egress's CONNECT host and
// host/mcpobserve.go's unchunked exec output — and because the file is a hash
// chain, every event after that line went with it: durable, guest-triggered
// destruction of the audit record.
//
// Both doors are closed now (internal/egress's hostile corpus and
// host/mcpobserve.go's chunking cover them directly). This exercises the
// backstop Append itself carries, at the level nobody has found a door to
// yet: an oversized Data field, on its own, with nothing between it and
// Append.
func TestHostileOversizedFieldCannotBreakTheChain(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "s1")
	if err != nil {
		t.Fatal(err)
	}
	// Comfortably past MaxLine on its own, so the guard has to do real work
	// rather than pass by coincidence.
	huge := strings.Repeat("x", 20<<20)

	problem := ""
	if err := rec.Append(Event{Type: TypeCommandStart}); err != nil {
		problem = fmt.Sprintf("a normal event before the giant one failed to append: %v", err)
	}
	if problem == "" {
		if err := rec.Append(Event{Type: TypeCommandOutput, Data: huge, Bytes: len(huge)}); err != nil {
			problem = fmt.Sprintf("a 20 MiB field made Append refuse the event outright: %v", err)
		}
	}
	if problem == "" {
		if err := rec.Append(Event{Type: TypeSessionEnd}); err != nil {
			problem = fmt.Sprintf("the event after the giant one failed to append: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	if problem == "" {
		blob, err := os.ReadFile(Path(root, "s1"))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
			if len(line) > MaxLine {
				problem = fmt.Sprintf("line %d is %d bytes, over MaxLine (%d)", i+1, len(line), MaxLine)
				break
			}
		}
	}
	if problem == "" {
		blob, err := os.ReadFile(Path(root, "s1"))
		if err != nil {
			t.Fatal(err)
		}
		n, _, verr := Verify(bytes.NewReader(blob))
		switch {
		case verr != nil:
			problem = fmt.Sprintf("the chain does not verify: %v", verr)
		case n != 3:
			problem = fmt.Sprintf("verified %d events, want 3 — the giant field made the rest unreadable", n)
		}
	}
	hostile.Holds(t, "recorder/oversized-field", problem)
}
