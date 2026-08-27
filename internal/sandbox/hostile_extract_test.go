package sandbox

import (
	"fmt"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
)

// The hostile corpus for validName's own claim about what debugfs receives
// (S5c).
//
// dumpFiles interpolates a guest-chosen name inside a double-quoted debugfs
// command: `dump -p "/<name>" <dest>`. validName rejected '/', NUL, "." and
// "..", names over 255 bytes, and every control character — but not a quote
// character, which is an ordinary printable byte, not a control one. A name
// containing '"' closes that quoted argument early, handing debugfs's own
// tokenizer whatever comes after as unquoted, unintended tokens. The comment
// directly above the dumpFiles line claimed quoting already covered this
// ("no newline, no control character... what is left is whitespace"), and
// that claim was false: a quote is neither a newline, a control character,
// nor whitespace.
//
// validName is a pure function over a string, so — like the exec and
// bootargs corpora — this needs no VM, no image and no mke2fs, and runs
// everywhere.
func TestHostileQuoteInEntryNameIsRefused(t *testing.T) {
	for _, tc := range []struct {
		key, name, why string
	}{
		{"extract/double-quote", `a" b`,
			`a double quote closes debugfs's quoted argument ("dump -p \"/<name>\" <dest>") early`},
		{"extract/single-quote", `a' b`,
			"a single quote is exactly as printable and exactly as unvetted for this position as a double quote"},
	} {
		t.Run(strings.TrimPrefix(tc.key, "extract/"), func(t *testing.T) {
			problem := ""
			if err := validName("workdir", tc.name); err == nil {
				problem = fmt.Sprintf("validName(%q) was accepted: %s", tc.name, tc.why)
			}
			hostile.Holds(t, tc.key, problem)
		})
	}

	// And an ordinary name — including one with real whitespace, which is
	// what the false comment was actually right to worry about — still goes
	// through. A guard that refused every printable character would have
	// made the check the problem.
	if err := validName("workdir", "a normal file name.txt"); err != nil {
		t.Errorf("an ordinary name with whitespace was refused: %v", err)
	}
}
