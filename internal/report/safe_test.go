package report

import (
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// Direct, function-level coverage for safe and safeBody (internal/report/
// safe.go) — the review that found safeBody had zero coverage (reverting it
// to a no-op passed the whole suite) mutation-tested both by hand; these are
// the tests that make that mutation fail without needing a full render.
// TestHostileValuesReachTextContentOnly and FuzzRunSectionRendersHostileStringsSafely
// (hostile_test.go) additionally exercise both through a real page now that
// the corpus carries an actual control-byte fixture, but a direct test of
// the two functions themselves is what catches "safeBody(s) == s always" on
// its own, independent of which fields the template happens to route
// through it.

func TestSafeLeavesOrdinaryStringsUntouched(t *testing.T) {
	for _, s := range []string{"", "worker-1", "example.com", "findings/*", "a normal path/to/file.txt"} {
		if got := safe(s); got != s {
			t.Errorf("safe(%q) = %q, want it unchanged", s, got)
		}
	}
}

// The exact regression the review's mutation test caught reverting `safe`
// to `s`: a control byte must change what safe returns, or a live report
// would carry it unescaped.
func TestSafeQuotesAControlByte(t *testing.T) {
	for _, s := range []string{"a\x00b", "a\x07b", "a\x1bb", "a\x7fb", "\x1b]0;pwned\x07"} {
		if got := safe(s); got == s {
			t.Errorf("safe(%q) returned the string unchanged; a control byte must change the output", s)
		}
	}
}

// safe is proto.SafeText; this pins that it stays that, rather than drift
// into a second, subtly different implementation of the same rule —
// compared directly against the real function, not a local restatement of
// its contract.
func TestSafeIsProtoSafeText(t *testing.T) {
	for _, s := range []string{"clean", "dirty\x01", "\x7f", "", "\x1b]0;pwned\x07"} {
		if got, want := safe(s), proto.SafeText(s); got != want {
			t.Errorf("safe(%q) = %q, want proto.SafeText's own answer %q", s, got, want)
		}
	}
}

func TestSafeBodyLeavesOrdinaryMultilineTextUntouched(t *testing.T) {
	s := "line one\nline two\r\nline three\twith a tab\n"
	if got := safeBody(s); got != s {
		t.Errorf("safeBody(%q) = %q, want it unchanged — \\t \\n \\r are not dangerous", s, got)
	}
}

// The exact regression the review's mutation test found completely
// uncaught: reverting safeBody(s) to `s` must change the output for a
// string carrying a real control byte, or every command-output/message-body
// surface is unprotected with nothing failing.
func TestSafeBodyReplacesControlBytesButKeepsTheRest(t *testing.T) {
	in := "\x1b]0;pwned\x07 normal text stays readable \x01\x1f\x7f end"
	got := safeBody(in)
	if got == in {
		t.Fatal("safeBody left a string with real control bytes completely unchanged")
	}
	if !strings.Contains(got, "normal text stays readable") {
		t.Errorf("safeBody(%q) = %q, lost legible content it should have kept", in, got)
	}
	for _, b := range []byte(got) {
		if isRawControlByte(b) {
			t.Fatalf("safeBody's own output still carries a raw control byte: 0x%02x", b)
		}
	}
	// \t \n \r survive: a command's real, multi-line output must not be
	// collapsed just because it also contains one dangerous byte elsewhere.
	multiline := "line one\n" + in + "\nline two\n"
	got = safeBody(multiline)
	if strings.Count(got, "\n") != strings.Count(multiline, "\n") {
		t.Errorf("safeBody changed the number of newlines: %d -> %d", strings.Count(multiline, "\n"), strings.Count(got, "\n"))
	}
}
