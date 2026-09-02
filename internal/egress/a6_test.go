package egress

import (
	"strings"
	"testing"
)

// The audit of 2026-09-01's A6: --allow org granted every .org host, credential
// binding included, silently. The suffix rule that makes "example.com" cover
// its own subdomains makes one bare label cover the whole TLD — so both doors
// that take a domain now require the shape of a real host.

func TestASingleLabelAllowEntryIsRefused(t *testing.T) {
	for _, bad := range []string{"org", "com", "io", "ORG", "IO."} {
		if err := CheckAllowList([]string{bad}); err == nil {
			t.Errorf("a bare TLD allow entry (%q) was accepted", bad)
		} else {
			if !strings.Contains(err.Error(), "bare top-level domain") {
				t.Errorf("the refusal for %q does not say what it is:\n%v", bad, err)
			}
			if !strings.Contains(err.Error(), "example."+strings.TrimSuffix(strings.ToLower(bad), ".")) {
				t.Errorf("the refusal for %q does not say what to type instead:\n%v", bad, err)
			}
		}
	}
	for _, good := range []string{"example.org", "api.github.com", "a.b"} {
		if err := CheckAllowList([]string{good}); err != nil {
			t.Errorf("a reasonable allow entry was refused: %v", err)
		}
	}
	// The refusal is the catalog one, so a reader can look it up.
	if err := CheckAllowList([]string{"org"}); err != nil && !strings.Contains(err.Error(), "[allow.single_label]") {
		t.Errorf("the refusal is not the catalog one:\n%v", err)
	}
}

// The credential door shares the rule: a secret bound to a bare TLD is the
// same internet-wide grant through the other door. validDomain is the
// predicate ParseSecretSpec runs the domain through.
func TestASecretCannotBindToABareTLD(t *testing.T) {
	t.Setenv("TOKEN", "whatever-value")
	for _, bad := range []string{"TOKEN@org", "TOKEN@io"} {
		if _, err := ParseSecretSpec(bad); err == nil {
			t.Errorf("%s parsed; a credential bound to a bare TLD was accepted", bad)
		} else if !strings.Contains(err.Error(), "bare top-level domain") {
			t.Errorf("the refusal for %s does not say what it is:\n%v", bad, err)
		}
	}
	if _, err := ParseSecretSpec("TOKEN@api.github.com"); err != nil {
		t.Errorf("a real credential binding was refused: %v", err)
	}
}

// The audit of 2026-09-01's M3/L13: A6 split an allow entry on "." to count its
// labels, so an IPv6 literal — one group when split on "." — was read as a
// bare top-level domain and refused, a host that was accepted before A6. An IP
// literal is one host, not a whole-TLD grant, and is exempt from the bare-TLD
// refusal at every door it enters.
func TestAnIPLiteralAllowEntryIsNotABareTLD(t *testing.T) {
	for _, ip := range []string{"2001:db8::1", "::1", "192.0.2.1", "[2001:db8::1]", "fe80::1"} {
		if err := CheckAllowList([]string{ip}); err != nil {
			t.Errorf("an IP-literal allow entry (%q) was refused: %v", ip, err)
		}
	}
	// The refusal it must not swallow still fires for an actual bare TLD.
	if err := CheckAllowList([]string{"org"}); err == nil {
		t.Error("a bare TLD is no longer refused; the IP exemption is too wide")
	}

	// validDomain — the credential door's predicate — shares the exemption, so
	// an IP literal is a domain a request could reach, and a bare TLD is not.
	for _, ip := range []string{"2001:db8::1", "192.0.2.1", "[2001:db8::1]"} {
		if !validDomain(ip) {
			t.Errorf("validDomain refused an IP literal as if it were a bare TLD: %q", ip)
		}
	}
	if validDomain("org") {
		t.Error("validDomain accepted a bare TLD after the IP exemption")
	}
}
