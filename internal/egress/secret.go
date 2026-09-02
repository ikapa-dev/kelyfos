package egress

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/ikapa-dev/kelyfos/internal/denial"
)

// Secret binds a credential to a domain. The value is read from the host
// environment and stays on the host: it is attached by the proxy to requests
// leaving for Domain, and never enters the guest in any form
// (docs/networking.md, decision D6).
type Secret struct {
	Name   string // the environment variable it came from, e.g. GITHUB_TOKEN
	Domain string // the domain it may be sent to
	Scheme string // Authorization scheme: "Bearer" or "Basic"
	Scope  Scope  // where it may be spent; the zero value is the whole domain
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
//
// A value shorter than minScrub is accepted — a short credential is the
// user's to choose and refusing one would break real credentials — but it is
// warned about at parse time, where the user can still choose differently:
// the echo suppression never matches below minScrub, so an origin that echoes
// a short credential hands it to the guest (audit 2026-09-01, A4). The
// warning is the package's one write to stderr, narrow and deliberate the way
// internal/sandbox's warnf is: a risk the user cannot see at parse time is a
// risk they learn about from the guest.
func ParseSecret(spec string) (*Secret, error) {
	parsed, err := ParseSecretSpec(spec)
	if err != nil {
		return nil, err
	}
	name := parsed.Name
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, fmt.Errorf("--secret %s: no environment variable %s on the host", spec, name)
	}
	if value == "" {
		return nil, fmt.Errorf("--secret %s: %s is set but empty", spec, name)
	}
	if len(value) < minScrub {
		fmt.Fprintf(os.Stderr, "kelyfos: secret %s (bound to %s) is %d bytes; values shorter than "+
			"%d are never scrubbed from responses, so an origin that echoes this credential "+
			"hands it to the guest — prefer a credential of at least %d bytes\n",
			name, parsed.Host, len(value), minScrub, minScrub)
	}
	return &Secret{
		Name: name, Domain: parsed.Host, Scheme: parsed.Scheme,
		Scope: Scope{Path: parsed.Path}, value: value,
	}, nil
}

// SecretSpec is a parsed --secret string, before the host environment is
// consulted. Separated from ParseSecret so the places that only need to
// understand the syntax — the policy-file check and the team-plan check — can
// use the same parser instead of writing a third and a fourth. There were four
// before P6-4, and the one in host/teamplan.go took everything after the "@" as
// the domain, which a path would have broken.
type SecretSpec struct {
	Name   string
	Host   string
	Path   string // "" when the spec named no path
	Scheme string
}

// ParseSecretSpec reads the grammar and nothing else.
//
//	NAME@host[:scheme][/path]
//
// The order of the steps is the design. The split on the first "/" happens
// BEFORE any other delimiter is looked for, so no character in a path can be
// mistaken for a scheme or anything else — which is what makes the grammar
// extensible without becoming ambiguous. plausibleHost already refuses "/" in a
// hostname, so the new delimiter cannot collide with what came before it.
func ParseSecretSpec(spec string) (SecretSpec, error) {
	var out SecretSpec

	// A target is a host and a path and nothing else. "?" and "#" would make it
	// a URL, and a query string is where credentials live on the APIs where
	// this feature is most attractive.
	for i := 0; i < len(spec); i++ {
		if c := spec[i]; c == '?' || c == '#' || c < 0x20 || c == 0x7f {
			return out, fmt.Errorf("--secret %q contains %q, which cannot appear in a secret binding", spec, string(c))
		}
	}

	name, target, ok := strings.Cut(spec, "@")
	if !ok || name == "" || target == "" {
		return out, fmt.Errorf("--secret must be NAME@domain, got %q", spec)
	}
	if strings.ContainsAny(name, "=/:") {
		return out, fmt.Errorf("--secret %q: %q is not an environment variable name", spec, name)
	}
	if strings.Contains(target, "@") {
		return out, fmt.Errorf("--secret %q has more than one @, so it names no single domain", spec)
	}

	hostpart, rest, hasPath := strings.Cut(target, "/")

	// The scheme is looked for in the host part only, exactly as it always was,
	// so ":BEARER" keeps working and "github.com:8080" stays the loud error it
	// has always been rather than becoming a credential bound to nothing.
	out.Scheme = "Bearer"
	if at := strings.LastIndex(hostpart, ":"); at > 0 {
		switch strings.ToLower(hostpart[at+1:]) {
		case "bearer":
		case "basic":
			out.Scheme = "Basic"
		default:
			return out, fmt.Errorf("unknown scheme %q in --secret %q (use bearer or basic)", hostpart[at+1:], spec)
		}
		hostpart = hostpart[:at]
	}
	if strings.Contains(hostpart, ":") {
		return out, fmt.Errorf("--secret %q: %q is not a domain", spec, hostpart)
	}

	if hasPath {
		// A path names one endpoint, so it binds this host exactly. "*." asks
		// for the opposite, and NormaliseDomain would strip it — turning the
		// broadest form a user can type into the narrowest binding in the
		// grammar, silently.
		if strings.HasPrefix(hostpart, "*.") {
			return out, fmt.Errorf("--secret %q: a path binds one host exactly, so %q cannot also be a wildcard", spec, hostpart)
		}
		out.Path = "/" + rest
		// Refused here, at the only door a scope enters by, with the form to
		// write instead (P7-14). covers withholds on the same rule, but a
		// refusal at parse time reaches the person who typed it, and a
		// withheld credential reaches them as a 401 from somewhere else.
		if err := canonicalScopePath(out.Path); err != nil {
			return out, fmt.Errorf("--secret %q: %w", spec, err)
		}
	}

	// The host is normalised; the path never is. Hosts are case-insensitive and
	// paths are not, and running the whole target through NormaliseDomain would
	// have lower-cased somebody's path segment.
	out.Host = NormaliseDomain(hostpart)
	// A bare TLD gets the same refusal the allowlist door gives, before the
	// generic shape error can swallow the reason (audit 2026-09-01, A6).
	if d := out.Host; d != "" && len(strings.Split(d, ".")) < 2 {
		return out, denial.AllowSingleLabel.Err(denial.V{
			"domain": d, "example": "example." + d})
	}
	if !validDomain(out.Host) {
		return out, fmt.Errorf("--secret %q does not name a domain a request could ever reach", spec)
	}
	out.Name = name
	return out, nil
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
// validDomain reports whether a normalised domain could ever match a host.
//
// Checking for emptiness was not enough, and the gap is narrow enough to be
// worth writing down. NormaliseDomain strips ONE trailing dot, so ".."
// normalises to ".", which is not empty — and secretFor strips the trailing dot
// from the host it is asked about, so it ends up comparing "" against ".". The
// credential binds to something no request can ever match: it goes out
// unauthenticated and the only symptom is a 401 from somewhere else.
//
// Found by the scheduled fuzz run on its first outing, by the same assertion
// that caught the github.com. case in P6-3 — three minutes a target found what
// forty-five seconds had not, which is the argument for having a schedule at
// all rather than only a per-push pass.
//
// The same predicate closes two silent misbinds that predate all of this:
// "T@a@b.com" bound the domain "a@b.com" and "T@host+GET" bound "host+get",
// both accepted, both unmatchable. A domain must look like a host — the same
// character rule the proxy applies to a request target — and must carry at
// least one letter or digit, which is what ".", "-" and ":" lack.
func validDomain(d string) bool {
	// An IP literal is the exact host it always matched before the audit of
	// 2026-09-01's A6 added the bare-TLD refusal (M3/L13). validDomain splits
	// on ".", so an IPv6 literal like 2001:db8::1 is one "label" and the
	// len(labels) < 2 rule below would refuse it as a whole-TLD grant — which
	// it is not. Exempted here so it is accepted as the host it names, exactly
	// as it was accepted before A6.
	if ipLiteral(d) {
		return true
	}
	if !plausibleHost(d) {
		return false
	}
	labels := strings.Split(d, ".")
	// A bare top-level domain — "org", "com" — is refused. The allowlist's
	// suffix rule turns one label into every host under it, and the audit of
	// 2026-09-01 (A6) demonstrated the whole-TLD grant live: --allow org
	// permitted gnu.org and httpbin.org alike, credential binding included.
	// A credential that binds to a TLD is the same grant through the other
	// door, so both doors require the shape of a real host: two labels or
	// more. The same check is exported as CheckAllowList for allowlist
	// entries, which arrive as a list rather than one spec.
	if len(labels) < 2 {
		return false
	}
	// Labels, because a name with an empty one — "..github.com", "a..b" — passes
	// every character test and still matches no host that exists. Enumerating
	// malformed shapes one at a time does not converge; requiring the shape of a
	// name does.
	for _, label := range labels {
		if label == "" {
			return false
		}
		alnum := false
		for i := 0; i < len(label); i++ {
			if c := label[i]; c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
				alnum = true
				break
			}
		}
		if !alnum {
			return false
		}
	}
	return true
}

// ipLiteral reports whether a normalised domain is actually an IP address
// literal — "192.0.2.1" or "2001:db8::1", the latter optionally bracketed. An
// IP literal has no labels: splitting "2001:db8::1" on "." yields a single
// group, which the bare-TLD refusals read as a one-label whole-TLD grant and
// reject. It is neither; it is the exact host it named. net.ParseIP is the
// authority on what is and is not an address, so the brackets are stripped and
// the rest is handed to it rather than pattern-matched (audit 2026-09-01,
// M3/L13).
func ipLiteral(d string) bool {
	return net.ParseIP(strings.TrimSuffix(strings.TrimPrefix(d, "["), "]")) != nil
}

func NormaliseDomain(s string) string {
	// TrimRight rather than TrimSuffix: one trailing dot is the fully-qualified
	// form, but two is not a name at all, and stripping only one left a domain
	// ending in a dot that could never match. secretFor and allowsHost trim the
	// trailing dot from the HOST they are asked about, so anything left on the
	// domain side is a guaranteed non-match — "0.." bound "0." and matched
	// nothing. Found by the scheduled fuzz run.
	return strings.TrimPrefix(strings.TrimRight(strings.ToLower(s), "."), "*.")
}

// CheckAllowList refuses an allowlist entry that is a bare top-level domain
// (audit 2026-09-01, A6). The suffix rule is otherwise correct — a two-label
// entry covers its own subdomains and nothing broader — but one label, "org"
// or "com", is every host under that TLD: egress to the internet at large and
// credential binding to match, accepted silently at parse time until the audit
// priced it. Refused at every door that takes an allowlist, consistently
// between allow and secret binding (validDomain requires the same two labels
// of a credential's domain).
func CheckAllowList(list []string) error {
	for _, a := range list {
		d := NormaliseDomain(a)
		if d == "" {
			continue
		}
		// An IP literal is not a bare TLD (M3/L13): it has no labels to count,
		// and it was accepted here before A6's bare-TLD refusal split on "."
		// and read an IPv6 literal's single "." group as a whole-TLD grant.
		if ipLiteral(d) {
			continue
		}
		if len(strings.Split(d, ".")) < 2 {
			return denial.AllowSingleLabel.Err(denial.V{
				"domain": d, "example": "example." + d})
		}
	}
	return nil
}

// secretFor returns the credential bound to a host, if any. Matching follows
// the allowlist rule: a bound domain covers its subdomains.
func (p *Policy) secretFor(host string) *Secret {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	// Domains are normalised once, when the secret is parsed.
	for _, s := range p.Secrets {
		if s.bindsHost(host) {
			return s
		}
	}
	return nil
}

// bindsHost reports whether this secret is bound to a host at all — the
// question that decides whether the proxy terminates, before any request has
// been read.
//
// A secret that names a path binds one host exactly. Naming an endpoint and
// then expanding to every subdomain of it would contradict the thing the path
// was written to do.
func (s *Secret) bindsHost(host string) bool {
	if s.Scope.Path != "" {
		return host == s.Domain
	}
	return host == s.Domain || strings.HasSuffix(host, "."+s.Domain)
}

// secretsFor is every secret bound to a host, in declaration order. The proxy
// picks among them per request, because two secrets on one host with different
// paths is the obvious use of endpoint scoping and a single first-match would
// make the second unreachable.
func (p *Policy) secretsFor(host string) []*Secret {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var out []*Secret
	for _, s := range p.Secrets {
		if s.bindsHost(host) {
			out = append(out, s)
		}
	}
	return out
}
