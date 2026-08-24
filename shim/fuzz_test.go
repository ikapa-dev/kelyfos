package shim

import (
	"strings"
	"testing"
)

// Fuzz targets for the E2B-compatible shim (P6-3).
//
// The shim is an unauthenticated local port — docs/threat-model.md §4 says so
// in those words — and it turns request fields into a command line for a guest
// shell. That makes its quoting the one function in this repository where a
// parsing bug is a command injection rather than a wrong answer.

// FuzzShellQuote asserts the property rather than the absence of a crash: a
// quoted string must survive a shell unchanged.
//
// The check is a reference unquoter rather than a real shell, because a harness
// that spawns a process per input is a harness nobody runs for three minutes.
// POSIX single-quoting has exactly one rule — everything inside '…' is literal,
// and a single quote is written by closing, escaping and reopening — so the
// reference is short enough to be obviously right.
func FuzzShellQuote(f *testing.F) {
	f.Add("ls")
	f.Add("a b")
	f.Add("it's")
	f.Add("'; rm -rf / #")
	f.Add(`'\''`)
	f.Add("$(whoami)")
	f.Add("`id`")
	f.Add("a\nb")
	f.Add("")
	f.Add("''''")

	f.Fuzz(func(t *testing.T, s string) {
		q := shellQuote(s)
		got, ok := unquoteSingle(q)
		if !ok {
			t.Fatalf("shellQuote(%q) = %q, which is not a well-formed single-quoted word", s, q)
		}
		if got != s {
			t.Fatalf("shellQuote(%q) = %q, which a shell reads as %q", s, q, got)
		}
	})
}

// unquoteSingle interprets a string of concatenated POSIX single-quoted words
// and backslash escapes, the way a shell would, and reports whether the input
// was well-formed. Anything outside a quoted section that is not a backslash
// escape means shellQuote emitted something a shell would interpret — which is
// the failure this exists to catch.
func unquoteSingle(q string) (string, bool) {
	var out strings.Builder
	i := 0
	for i < len(q) {
		switch q[i] {
		case '\'':
			i++
			for {
				if i >= len(q) {
					return "", false // unterminated
				}
				if q[i] == '\'' {
					i++
					break
				}
				out.WriteByte(q[i])
				i++
			}
		case '\\':
			if i+1 >= len(q) {
				return "", false
			}
			out.WriteByte(q[i+1])
			i += 2
		default:
			// A bare character outside quotes. Only a shell metacharacter is
			// dangerous, but nothing shellQuote emits should be bare at all,
			// so any of it is a failure worth reporting.
			return "", false
		}
	}
	return out.String(), true
}

// FuzzDecodeBase64Lines drives the decoder for wrapped base64 coming back from
// a guest command. The bytes are the guest's, and the result is handed to an
// SDK client as file contents.
func FuzzDecodeBase64Lines(f *testing.F) {
	f.Add([]byte("aGVsbG8="))
	f.Add([]byte("aGVs\nbG8=\n"))
	f.Add([]byte("  aGVs bG8=  "))
	f.Add([]byte("not base64!"))
	f.Add([]byte(""))
	f.Add([]byte("=========="))

	f.Fuzz(func(t *testing.T, out []byte) {
		_, _ = decodeBase64Lines(out)
	})
}
