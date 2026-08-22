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
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("--secret %s: no environment variable %s on the host", spec, name)
	}
	if value == "" {
		return nil, fmt.Errorf("--secret %s: %s is set but empty", spec, name)
	}
	return &Secret{Name: name, Domain: strings.ToLower(domain), Scheme: scheme, value: value}, nil
}

// secretFor returns the credential bound to a host, if any. Matching follows
// the allowlist rule: a bound domain covers its subdomains.
func (p *Policy) secretFor(host string) *Secret {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, s := range p.Secrets {
		if host == s.Domain || strings.HasSuffix(host, "."+s.Domain) {
			return s
		}
	}
	return nil
}
