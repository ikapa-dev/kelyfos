package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// Routed to this workstream from the record workstream's review:
// host/servemcptools.go put sandbox.Exec's error text straight into
// EvError.Message, and one of that function's error paths is
//
//	fmt.Errorf("guest sent an unknown stream %q", proto.SafeText(resp.Stream))
//
// (internal/sandbox/exec.go:135). resp.Stream is a guest-chosen string.
// proto.SafeText bounds its CHARACTER CLASS and not its LENGTH, so a guest that
// answers with a multi-megabyte stream name put a multi-megabyte, guest-chosen
// string into the chain — F12's shape on a field nobody had looked at. The
// erase sink fingerprints it now, which makes an erased chain clean and leaves
// an un-erased one exactly as it was.
func TestARecordedErrorMessageIsBoundedAndSaysSo(t *testing.T) {
	// The real path, built the way internal/sandbox/exec.go builds it.
	huge := strings.Repeat("A", 4<<20)
	err := fmt.Errorf("guest sent an unknown stream %q", proto.SafeText(huge))

	got := recordedErrorMessage(err)
	if len(got) > maxRecordedErrorMessage {
		t.Errorf("a %d-byte error reached the chain as %d bytes, over the %d bound",
			len(err.Error()), len(got), maxRecordedErrorMessage)
	}
	if !strings.Contains(got, "elided") {
		t.Errorf("the message was truncated without saying so: %q", got)
	}
	// The head survives, or truncation has thrown away the diagnosis with the
	// payload.
	if !strings.Contains(got, "guest sent an unknown stream") {
		t.Errorf("truncation lost the part that says what went wrong: %q", got)
	}
}

func TestAnOrdinaryRecordedErrorIsUntouched(t *testing.T) {
	for _, msg := range []string{
		"dial vsock: connection refused",
		"the command did not finish within 30s",
		"",
	} {
		if got := recordedErrorMessage(errors.New(msg)); got != msg {
			t.Errorf("recordedErrorMessage(%q) = %q, want it unchanged", msg, got)
		}
	}
	if got := recordedErrorMessage(nil); got != "" {
		t.Errorf("recordedErrorMessage(nil) = %q, want empty", got)
	}
}

// SafeText bounds character class; this bounds length. Both, because an error
// path that does not already call SafeText is one nobody has to remember.
func TestARecordedErrorMessageCarriesNoControlBytes(t *testing.T) {
	got := recordedErrorMessage(fmt.Errorf("guest said \x1b[2J\x1b[3J%s", strings.Repeat("B", 1<<20)))
	for _, r := range got {
		if r != '\t' && r != '\n' && (r < 0x20 || r == 0x7f) {
			t.Fatalf("a raw control byte reached the chain: %q", got)
		}
	}
	if len(got) > maxRecordedErrorMessage {
		t.Errorf("length %d over the %d bound", len(got), maxRecordedErrorMessage)
	}
}
