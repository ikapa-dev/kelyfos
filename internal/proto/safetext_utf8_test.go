package proto

import (
	"bytes"
	"testing"
)

// The adversarial cross-check (2026-09-01): ranging over invalid UTF-8 yields
// U+FFFD, which is printable, so each raw bad byte passed SafeText verbatim —
// and 0x9b is CSI on an 8-bit terminal, the same rewriting power as ESC [.
// The sanitiser quotes any string that is not valid UTF-8.
func TestSafeTextQuotesInvalidUTF8(t *testing.T) {
	for _, hostile := range []string{
		"\x9b[31mred",    // 8-bit CSI
		"\xff\xfeprefix", // BOM-shaped garbage
		"ok\x80raw",      // one bad byte inside printable text
		"\xc0\xaf",       // overlong slash
	} {
		got := SafeText(hostile)
		if bytes.Contains([]byte(got), []byte{0x9b}) || bytes.Contains([]byte(got), []byte{0x80}) ||
			bytes.Contains([]byte(got), []byte{0xc0}) || bytes.Contains([]byte(got), []byte{0xff}) {
			t.Errorf("a raw invalid-UTF-8 byte reached the record: %q -> %q (bytes % x)",
				hostile, got, got)
		}
	}
	// Valid UTF-8 that was already safe is untouched.
	if got := SafeText("compiling foo.c"); got != "compiling foo.c" {
		t.Errorf("a clean line was rewritten: %q", got)
	}
	// Control characters in valid UTF-8 still quote, as before.
	if got := SafeText("a\x1bb"); got == "a\x1bb" {
		t.Error("an escape character passed through")
	}
}
