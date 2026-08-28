package report

import (
	"strings"
	"testing"
)

// P7-17/F1, the report's half. safe is proto.SafeText and safeBody keys on the
// same predicate, so the HTML page inherited the same blind spot — arguably
// worse there, because the export is the artefact meant to be read by someone
// who was not present. html/template escapes `< > & ' "` and nothing else, and
// a bidirectional override is none of those.
//
// bidiRTL renders as "acceptable" and compares as its reverse.
const bidiRTL = "‮elbatpecca"

func TestF1_SafeQuotesABidiOverride(t *testing.T) {
	if got := safe(bidiRTL); got == bidiRTL {
		t.Errorf("safe(%q) returned the string unchanged", bidiRTL)
	}
	if got := safe("worker-1"); got != "worker-1" {
		t.Errorf("safe(%q) = %q, want it unchanged", "worker-1", got)
	}
}

func TestF1_SafeBodyReplacesABidiOverride(t *testing.T) {
	in := "before " + bidiRTL + " after\n"
	got := safeBody(in)
	if strings.ContainsRune(got, 0x202e) {
		t.Errorf("safeBody passed a right-to-left override through: %q", got)
	}
	if !strings.Contains(got, "before ") || !strings.Contains(got, " after") {
		t.Errorf("safeBody(%q) = %q, lost content it should have kept", in, got)
	}
	// Ordinary non-ASCII output is untouched: the clause must not turn a
	// legitimately international transcript into replacement characters.
	keep := "line one · Καλημέρα\nline two → 日本語\n"
	if got := safeBody(keep); got != keep {
		t.Errorf("safeBody(%q) = %q, want it unchanged", keep, got)
	}
}

// The corpus case the review asked for by name: the same override as a store
// key, a command and a message body, through a real render. Nothing invisible
// reaches the page, and the value is still counted rather than dropped.
func TestF1_NoBidiOverrideSurvivesARender(t *testing.T) {
	html := render(t, hostileEvents())
	page := stripIsland(t, html)
	for _, r := range page {
		switch r {
		case 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // the embeddings and overrides
			0x2066, 0x2067, 0x2068, 0x2069, // the isolates
			0x200b, 0x200c, 0x200d, 0x00ad: // zero-width and soft hyphen
			t.Fatalf("U+%04X reached the rendered page", r)
		}
	}
	// The fixture really did carry one, or the loop above proved nothing.
	if !strings.Contains(html, `elbatpecca`) {
		t.Fatal("the bidi fixture never reached the page at all; this test would pass vacuously")
	}
}
