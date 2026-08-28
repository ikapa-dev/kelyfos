package proto

import (
	"strings"
	"testing"
)

// SafeBody is the terminal-safe body sanitiser the review asked for: command
// output is legitimately multi-line and legitimately coloured, so quoting the
// whole blob on one stray byte would be a larger regression than the property
// being defended. What it must never pass through is OSC (ESC ]) — window
// title and hyperlink injection — or the CSI screen controls J and H.
func TestF20_SafeBodyKeepsOutputReadableAndStripsTheDangerousParts(t *testing.T) {
	t.Run("ordinary multi-line output is untouched", func(t *testing.T) {
		in := "line one\nline two\twith a tab\nline three\n"
		if got := SafeBody(in); got != in {
			t.Errorf("SafeBody(%q) = %q, want it unchanged", in, got)
		}
	})

	t.Run("SGR colour survives", func(t *testing.T) {
		in := "\x1b[31mFAIL\x1b[0m ok\n\x1b[1;32;40mgreen\x1b[m\n"
		if got := SafeBody(in); got != in {
			t.Errorf("SafeBody stripped an SGR colour sequence: %q -> %q", in, got)
		}
	})

	t.Run("OSC and screen control never survive", func(t *testing.T) {
		for _, in := range []string{
			"\x1b]0;pwned\x07",           // OSC title set, BEL-terminated
			"\x1b]8;;http://evil\x1b\\x", // OSC 8 hyperlink
			"\x1b[2J\x1b[3J",             // erase display and scrollback
			"\x1b[1;1H",                  // cursor home
			"\x1b[1A\x1b[2K\r",           // up a line, erase it, return
			"\x1bc",                      // RIS, full reset
			"a\x00b\x07c\x7fd",           // bare C0 and DEL
		} {
			got := SafeBody(in)
			if strings.ContainsRune(got, 0x1b) {
				t.Errorf("SafeBody(%q) left a raw ESC: %q", in, got)
			}
			for _, r := range got {
				if r == '\t' || r == '\n' {
					continue
				}
				if r < 0x20 || r == 0x7f {
					t.Errorf("SafeBody(%q) left control byte %#x: %q", in, r, got)
				}
			}
		}
	})

	t.Run("legible content around a hostile sequence is kept", func(t *testing.T) {
		got := SafeBody("before \x1b]0;pwned\x07 after\n")
		if !strings.Contains(got, "before ") || !strings.Contains(got, " after") {
			t.Errorf("SafeBody(%q) lost content it should have kept", got)
		}
		if !strings.HasSuffix(got, "\n") {
			t.Errorf("SafeBody dropped the trailing newline: %q", got)
		}
	})

	t.Run("a carriage return cannot overwrite the line", func(t *testing.T) {
		// `kelyfos log` prints each output line behind a fixed prefix. A \r
		// inside one lets the guest drive the cursor back over that prefix and
		// print whatever it likes in the host's own voice, so \r is not in the
		// keep list even though \n and \t are.
		if got := SafeBody("real output\rfake host line"); strings.ContainsRune(got, '\r') {
			t.Errorf("SafeBody passed a carriage return through: %q", got)
		}
	})
}
