package egress

import (
	"strings"
	"testing"
)

// The security review of 2026-09-03: an IP literal in the allowlist or in a
// credential binding is matched exactly, never by suffix, and an entry made
// only of numeric labels is refused at every door that takes one.

func TestReview_AnIPLiteralTargetIsNeverSuffixMatched(t *testing.T) {
	p := &Policy{Allow: []string{"0.1", "example.com"}}
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "192.168.0.1", "169.254.0.1"} {
		if p.allowsHost(host) {
			t.Errorf("allow [0.1] admitted %s by suffix", host)
		}
	}
	if !p.allowsHost("api.example.com") || !p.allowsHost("example.com") {
		t.Error("the domain suffix rule must still hold for names")
	}
}

func TestReview_AnIPLiteralEntryMatchesOnlyItself(t *testing.T) {
	p := &Policy{Allow: []string{"192.0.2.10", "2001:db8::1"}}
	if !p.allowsHost("192.0.2.10") || !p.allowsHost("2001:db8::1") {
		t.Error("a literal entry must admit the address it names")
	}
	for _, host := range []string{"1.192.0.2.10", "x.192.0.2.10", "192.0.2.100"} {
		if p.allowsHost(host) {
			t.Errorf("a literal entry admitted %s", host)
		}
	}
}

func TestReview_ACredentialBoundToANumericTailBindsNoAddress(t *testing.T) {
	s := &Secret{Name: "T", Domain: "0.1"}
	if s.bindsHost("127.0.0.1") {
		t.Error("a binding to 0.1 attached to 127.0.0.1 by suffix")
	}
	lit := &Secret{Name: "T", Domain: "192.0.2.10"}
	if !lit.bindsHost("192.0.2.10") || lit.bindsHost("1.192.0.2.10") {
		t.Error("a literal binding must cover exactly the address it names")
	}
}

func TestReview_NumericPseudoDomainsAreRefusedAtBothDoors(t *testing.T) {
	for _, entry := range []string{"0.1", "168.0.1", "254.169.254"} {
		if err := CheckAllowList([]string{entry}); err == nil {
			t.Errorf("CheckAllowList accepted %q", entry)
		} else if !strings.Contains(err.Error(), "not a domain") {
			t.Errorf("CheckAllowList refused %q for the wrong reason: %v", entry, err)
		}
		if _, err := ParseSecretSpec("T@" + entry); err == nil {
			t.Errorf("ParseSecretSpec accepted T@%s", entry)
		}
	}
	// A whole address is still an ordinary, exact entry, and a name with a
	// numeric label somewhere is still a name.
	for _, entry := range []string{"192.0.2.10", "[2001:db8::1]", "3.example.com", "example.123"} {
		if err := CheckAllowList([]string{entry}); err != nil {
			t.Errorf("CheckAllowList refused %q: %v", entry, err)
		}
	}
	if _, err := ParseSecretSpec("T@192.0.2.10"); err != nil {
		t.Errorf("a literal binding was refused: %v", err)
	}
}
