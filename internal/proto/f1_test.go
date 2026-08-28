package proto

import (
	"strings"
	"testing"
)

// P7-17/F1 — the guest text sanitiser misses Unicode format characters.
//
// SafeText's own doc comment says why it exists: "a control character in one
// of those is not a display nuisance — it is the guest deciding what the
// host's output looks like." Its predicate was ASCII-only, so the whole Cf
// category sailed through — the bidirectional overrides and isolates, the
// Trojan Source class, which reorder how a line renders without changing a
// byte of its logical content, in a terminal and in a browser alike.
//
// bidiRTL is the worked example: rendered, "‮elbatpecca" reads as
// "acceptable" and compares as its reverse. A guest gets to choose how its own
// audit record reads to a person — a domain in a blocked-egress line, a path,
// a store key, a command.
const bidiRTL = "‮elbatpecca"

func TestF1_SafeTextQuotesEveryNonPrintableRune(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"right-to-left override U+202E", bidiRTL},
		{"first strong isolate U+2068", "worker⁨-1"},
		{"pop directional isolate U+2069", "worker-1⁩"},
		{"left-to-right isolate U+2066", "⁦findings/*"},
		{"right-to-left isolate U+2067", "⁧findings/*"},
		{"zero-width joiner U+200D", "git‍hub.com"},
		{"zero-width space U+200B", "exam​ple.com"},
		{"soft hyphen U+00AD", "exam­ple.com"},
		{"no-break space U+00A0", "/work/two words"},
		{"line separator U+2028", "a b"},
		{"unassigned U+0378", "a͸b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SafeText(c.in)
			if got == c.in {
				t.Fatalf("SafeText(%q) returned the string unchanged", c.in)
			}
			// strconv.Quote is the escape, and it already renders these; the
			// point of the finding is only that it was never reached.
			if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
				t.Errorf("SafeText(%q) = %q, want the quoted form", c.in, got)
			}
			for _, r := range got {
				if r > 0x7f {
					t.Errorf("SafeText(%q) = %q still carries U+%04X", c.in, got, r)
				}
			}
		})
	}
}

// The other half of the same predicate: widening it must not start quoting the
// ordinary non-ASCII this product prints on every line of every report and
// every replay. If this fails, the fix is worse than the finding.
func TestF1_SafeTextStillLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{
		"",
		"worker-1",
		"api.github.com",
		"findings/*",
		"/work/src/main.go",
		"master → worker-1", // the arrow the lane view and the report both draw
		"send · 40 bytes",   // the middle dot every detail line uses
		"an em — dash",
		"Καλημέρα",          // Greek
		"日本語のパス",            // CJK
		"emoji 🎉 in a name", // an astral-plane symbol
		"café",              // precomposed
		"café",             // decomposed: U+0301 is a combining mark, and printable
	} {
		if got := SafeText(s); got != s {
			t.Errorf("SafeText(%q) = %q, want it unchanged", s, got)
		}
	}
}

// SafeBody is the body-shaped counterpart and gets the same clause: command
// output legitimately contains non-ASCII, and does not legitimately contain
// direction overrides.
func TestF1_SafeBodyReplacesFormatCharactersButKeepsRealText(t *testing.T) {
	got := SafeBody("before " + bidiRTL + " after\n")
	if strings.ContainsRune(got, 0x202e) {
		t.Errorf("SafeBody passed a right-to-left override through: %q", got)
	}
	if !strings.Contains(got, "before ") || !strings.Contains(got, " after") {
		t.Errorf("SafeBody(%q) lost content it should have kept", got)
	}
	if !strings.ContainsRune(got, '�') {
		t.Errorf("SafeBody did not mark the removal with U+FFFD: %q", got)
	}

	// Ordinary multi-line, non-ASCII, coloured output survives whole.
	keep := "\x1b[31mΣΦΑΛΜΑ\x1b[0m: 日本語\nline two · ok\n"
	if got := SafeBody(keep); got != keep {
		t.Errorf("SafeBody(%q) = %q, want it unchanged", keep, got)
	}
}
