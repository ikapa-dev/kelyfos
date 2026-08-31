package egress

import (
	"strings"
	"testing"
)

// ST-4.2's property tests for the allowlist matcher: hostile names, pinned
// against the semantics the docs and IA-I1 state. This is a pin, not an
// endorsement — the matcher is byte-lexical (one ToLower and one trailing-dot
// trim, then the documented comparison), so unicode names are neither
// normalised nor punycode-decoded, and a name that is "the same" only after
// normalisation does NOT match. If that ever changes — IDNA normalisation at
// the boundary, say — this table is what flips, loudly, beside a decision row.

func TestAllowsHost_HostileNamesPinTheSemantics(t *testing.T) {
	p := &Policy{Allow: []string{"example.com"}}
	cases := []struct {
		host string
		want bool
		why  string
	}{
		// The documented core.
		{"example.com", true, "exact"},
		{"www.example.com", true, "dot-anchored subdomain"},
		{"EXAMPLE.COM", true, "case is lowered"},
		{"example.com.", true, "the trailing dot is trimmed before matching"},
		// The traps.
		{"notexample.com", false, "the suffix trap: HasSuffix without the dot anchor would pass this"},
		{"example.com.evil.test", false, "a suffix that merely ends in the allowlisted name"},
		{"", false, "an empty host matches nothing"},
		{".", false, "a lone dot trims to the empty host"},
		{"a..example.com", true, "PINNED: an empty label above the entry still ends in .example.com — the dot anchor is lexical, not label-aware"},
		// Unicode is byte-lexical: no NFC/NFD folding, no punycode decode.
		{"exаmple.com", false, "Cyrillic а is a different byte sequence, matched byte-lexically"},
		{"xn--сdst-3na.example.com", true, "PINNED: punycode is opaque ASCII, and an ASCII label under the entry is an ordinary subdomain"},
		{"xn--e1afmkfd.example.com", true, "a punycode label under the allowlisted domain is an ordinary subdomain"},
		{"cafe\u0301.example.com", true, "NFD bytes form an ordinary dot-anchored subdomain"},
	}
	for _, c := range cases {
		if got := p.allowsHost(c.host); got != c.want {
			t.Errorf("allowsHost(%q) = %v, want %v (%s)", c.host, got, c.want, c.why)
		}
	}
}

// Two invariants the semantics imply, checked over generated names rather
// than a table, because a table only covers the cases its author thought of.
func TestAllowsHost_Invariants(t *testing.T) {
	p := &Policy{Allow: []string{"example.com"}}
	hostile := []string{
		"", ".", "..", "a", "a.", ".a", "example.com", "EXAMPLE.COM", "example.com.",
		"www.example.com", "xwww.example.com", "notexample.com", "example.community",
		"example.com.", "example..com", "EXAMPLE.com.", "EXAMPLE.COM.evil.test",
		"xn--e1afmkfd.example.com", "cafe\u0301.example.com", "example.com ",
		" example.com", "example.com\t",
	}
	for _, h := range hostile {
		got := p.allowsHost(h)
		// Invariant 1: whatever matches, matches without its trailing dot too —
		// the trim happens before the comparison, so a dot can only widen.
		trimmed := strings.TrimSuffix(h, ".")
		if got && !p.allowsHost(trimmed) {
			t.Errorf("allowsHost(%q) but not allowsHost(%q): the trailing-dot trim is not idempotent", h, trimmed)
		}
		// Invariant 2: a match implies the name is the allowlist entry or ends
		// in dot+entry AFTER normalisation — the property IA-I1 described and
		// the docs state. Anything else is a suffix leak.
		if got {
			norm := strings.ToLower(strings.TrimSuffix(h, "."))
			if norm != "example.com" && !strings.HasSuffix(norm, ".example.com") {
				t.Errorf("allowsHost(%q) matched without being the entry or a dot-anchored subdomain", h)
			}
		}
	}
}
