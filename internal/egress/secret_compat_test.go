package egress

import "testing"

// The `--secret` grammar as it stands, pinned before it is extended.
//
// P6-4 adds endpoint locking and method scoping to this spec string, and P6-14
// then freezes the result in the v1.0 compatibility promise. Between those two
// facts sits the thing worth guarding: every spec a user has already written
// must go on meaning exactly what it meant, and "exactly" includes the parts
// nobody thinks about — which half of a colon is the scheme, what a suffix match
// covers, what is refused and with what shape of message.
//
// So this table is written against the CURRENT behaviour and passes today. It is
// not a description of what the grammar should become; it is a record of what it
// already promised, so that an extension which quietly changes an old meaning
// fails here rather than in somebody's pipeline.
func TestTheExistingSecretGrammarKeepsItsMeaning(t *testing.T) {
	t.Setenv("KELYFOS_COMPAT_TOKEN", "value")

	for _, tc := range []struct {
		spec       string
		wantDomain string
		wantScheme string
		wantErr    bool
	}{
		// The shapes the documentation shows.
		{spec: "KELYFOS_COMPAT_TOKEN@github.com", wantDomain: "github.com", wantScheme: "Bearer"},
		{spec: "KELYFOS_COMPAT_TOKEN@api.github.com", wantDomain: "api.github.com", wantScheme: "Bearer"},
		{spec: "KELYFOS_COMPAT_TOKEN@github.com:bearer", wantDomain: "github.com", wantScheme: "Bearer"},
		{spec: "KELYFOS_COMPAT_TOKEN@github.com:basic", wantDomain: "github.com", wantScheme: "Basic"},
		{spec: "KELYFOS_COMPAT_TOKEN@github.com:BEARER", wantDomain: "github.com", wantScheme: "Bearer"},

		// Domain normalisation, which P6-3 made one function. A domain that
		// normalises away is refused rather than bound to nothing.
		{spec: "KELYFOS_COMPAT_TOKEN@GitHub.COM", wantDomain: "github.com", wantScheme: "Bearer"},
		{spec: "KELYFOS_COMPAT_TOKEN@github.com.", wantDomain: "github.com", wantScheme: "Bearer"},
		{spec: "KELYFOS_COMPAT_TOKEN@*.github.com", wantDomain: "github.com", wantScheme: "Bearer"},
		{spec: "KELYFOS_COMPAT_TOKEN@.", wantErr: true},

		// Refused from v1.0, where they were accepted before and bound a
		// credential to something no request could ever match. Listed here
		// rather than left out, because a behaviour that CHANGED is exactly
		// what a compatibility pin is for: these are the deliberate breaks.
		// ".." normalised to "." and was found by the scheduled fuzz run;
		// the other two predate it and were found by the same predicate.
		{spec: "KELYFOS_COMPAT_TOKEN@..", wantErr: true},
		{spec: "KELYFOS_COMPAT_TOKEN@a@b.com", wantErr: true},
		{spec: "KELYFOS_COMPAT_TOKEN@host+GET", wantErr: true},
		{spec: "KELYFOS_COMPAT_TOKEN@-", wantErr: true},

		// Refusals, which are part of the contract too.
		{spec: "KELYFOS_COMPAT_TOKEN@github.com:digest", wantErr: true},
		{spec: "KELYFOS_COMPAT_TOKEN", wantErr: true},
		{spec: "@github.com", wantErr: true},
		{spec: "KELYFOS_COMPAT_TOKEN@", wantErr: true},
		{spec: "", wantErr: true},
		{spec: "KELYFOS_NOT_SET_ANYWHERE@github.com", wantErr: true},
	} {
		got, err := ParseSecret(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSecret(%q) was accepted; it has always been refused", tc.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSecret(%q) failed: %v", tc.spec, err)
			continue
		}
		if got.Domain != tc.wantDomain {
			t.Errorf("ParseSecret(%q).Domain = %q, want %q", tc.spec, got.Domain, tc.wantDomain)
		}
		if got.Scheme != tc.wantScheme {
			t.Errorf("ParseSecret(%q).Scheme = %q, want %q", tc.spec, got.Scheme, tc.wantScheme)
		}
	}
}

// A bound domain covers its subdomains and nothing else. This is the rule a
// reader of docs/threat-model.md is told to reason about when deciding what a
// credential can be spent on, so it is pinned separately from the parse.
func TestABoundDomainCoversItsSubdomainsAndNothingElse(t *testing.T) {
	t.Setenv("KELYFOS_COMPAT_TOKEN", "value")
	s, err := ParseSecret("KELYFOS_COMPAT_TOKEN@github.com")
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Secrets: []*Secret{s}}

	for _, host := range []string{"github.com", "api.github.com", "raw.githubusercontent.github.com", "GITHUB.COM", "github.com."} {
		if p.secretFor(host) == nil {
			t.Errorf("a credential bound to github.com did not match %q", host)
		}
	}
	for _, host := range []string{"github.com.evil.com", "notgithub.com", "example.com", "", "com"} {
		if p.secretFor(host) != nil {
			t.Errorf("a credential bound to github.com matched %q, which is not it or a subdomain of it", host)
		}
	}
}
