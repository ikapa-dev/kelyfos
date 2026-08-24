package egress

import (
	"fmt"
	"os"
	"strings"
)

// Secret binds a credential to a domain. The value is read from the host
// environment and stays on the host: it is attached by the proxy to requests
// leaving for Domain, and never enters the guest in any form
// (docs/networking.md, decision D6).
type Secret struct {
	Name   string // the environment variable it came from, e.g. GITHUB_TOKEN
	Domain string // the domain it may be sent to
	Scheme string // Authorization scheme: "Bearer" or "Basic"
	value  string // never logged, never serialized, never sent to the guest
}

// Header is the Authorization header value to attach.
func (s *Secret) Header() string { return s.Scheme + " " + s.value }

// String deliberately omits the value, so a Secret cannot leak through a stray
// %v in a log line — the failure that makes every other precaution pointless.
func (s *Secret) String() string {
	return fmt.Sprintf("Secret{%s@%s scheme=%s}", s.Name, s.Domain, s.Scheme)
}

// ParseSecret reads a --secret NAME@domain specification and looks the value up
// in the host environment.
//
// An optional scheme suffix covers the split in practice: an API usually wants
// "Bearer", while git over HTTPS authenticates with Basic.
//
//	GITHUB_TOKEN@api.github.com
//	GITHUB_TOKEN@github.com:basic
func ParseSecret(spec string) (*Secret, error) {
	scheme := "Bearer"
	if at := strings.LastIndex(spec, ":"); at > 0 && !strings.Contains(spec[at:], "@") {
		switch strings.ToLower(spec[at+1:]) {
		case "bearer":
		case "basic":
			scheme = "Basic"
		default:
			return nil, fmt.Errorf("unknown scheme %q in --secret %q (use bearer or basic)", spec[at+1:], spec)
		}
		spec = spec[:at]
	}

	name, domain, ok := strings.Cut(spec, "@")
	if !ok || name == "" || domain == "" {
		return nil, fmt.Errorf("--secret must be NAME@domain, got %q", spec)
	}
	domain = NormaliseDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("--secret %q names no domain", spec)
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("--secret %s: no environment variable %s on the host", spec, name)
	}
	if value == "" {
		return nil, fmt.Errorf("--secret %s: %s is set but empty", spec, name)
	}
	return &Secret{Name: name, Domain: domain, Scheme: scheme, value: value}, nil
}

// NormaliseDomain puts a policy domain into the single form that matching
// compares against.
//
// It exists because four copies of this expression had drifted into three
// different behaviours. allowsHost normalised both the host and the allowlist
// entry; secretFor normalised only the host, and ParseSecret stored the domain
// lowercased and otherwise as typed; containsDomain normalised only the entry.
// So `--allow github.com.` worked and `--secret TOKEN@github.com.` did not —
// the credential was bound to a domain that could never match, the request went
// out unauthenticated, and the only symptom was a 401 from somewhere else.
// Found by FuzzParseSecret (P6-3), which asserts that a secret matches the
// domain it was just bound to.
//
// A trailing dot is the fully-qualified form of the same name; a leading `*.`
// is how people write a wildcard, and the suffix rule already covers subdomains
// without it.
func NormaliseDomain(s string) string {
	return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(s), "."), "*.")
}

// secretFor returns the credential bound to a host, if any. Matching follows
// the allowlist rule: a bound domain covers its subdomains.
func (p *Policy) secretFor(host string) *Secret {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Domains are normalised once, when the secret is parsed.
	for _, s := range p.Secrets {
		if host == s.Domain || strings.HasSuffix(host, "."+s.Domain) {
			return s
		}
	}
	return nil
}
