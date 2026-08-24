package egress

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// Fuzz targets for the egress proxy (P6-3).
//
// Two hostile directions meet in this package. The guest composes the requests,
// and the guest runs untrusted agent code; the upstream composes the responses,
// and an allowlisted domain is not a trusted one. What makes it the sharpest
// surface in the product is what sits one line away: for a secret-bound domain
// the proxy attaches a credential to the request it parsed. A parsing bug here
// does not merely crash — it can hand the credential to a destination the
// policy never approved, because policy and destination are both derived from
// the same parse.

// FuzzSplitTarget drives the function every policy decision keys on.
//
// `splitTarget` decides the host and port that `allowsHost`, `allowsPort` and
// `secretFor` are then asked about, and that the flight recorder writes down.
// If it can be made to return something that is not the destination the
// connection actually reaches, every check downstream is answering about the
// wrong thing.
func FuzzSplitTarget(f *testing.F) {
	f.Add([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"))
	f.Add([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("CONNECT example.com HTTP/1.1\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: EXAMPLE.COM:80\r\n\r\n"))
	// The shapes worth being suspicious about: a userinfo, a port that is not a
	// port, an embedded path, and a second host header.
	f.Add([]byte("GET http://user@evil.com/ HTTP/1.1\r\nHost: good.com\r\n\r\n"))
	f.Add([]byte("CONNECT good.com:-1 HTTP/1.1\r\n\r\n"))
	f.Add([]byte("CONNECT good.com:99999 HTTP/1.1\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		// The body is never read here, so nothing can block on it.
		host, port, err := splitTarget(req)
		if err != nil {
			return
		}
		if host == "" {
			t.Fatalf("accepted a target with an empty host, from %q", data)
		}
		if host != strings.ToLower(host) {
			t.Fatalf("host %q is not lowercased, so policy matching is case-dependent", host)
		}
		// A host that carries any of these is not a hostname: it is a hostname
		// plus something the parse should have taken off, and whatever it is
		// would be compared against the allowlist as if it were part of the
		// name.
		for _, bad := range []string{"/", " ", "\t", "\r", "\n", "@"} {
			if strings.Contains(host, bad) {
				t.Fatalf("host %q contains %q — the allowlist would be asked about a string that is not a hostname", host, bad)
			}
		}
		if port < 1 || port > 65535 {
			t.Fatalf("accepted port %d, which is not a port, from %q", port, data)
		}
	})
}

// FuzzParseSecret drives the `--secret NAME@domain[:scheme]` grammar.
//
// The domain it produces is what a credential is bound to, and binding is a
// suffix match — so a domain this function accepts wrongly is a credential
// attached to hosts nobody approved, or attached to nothing at all and silently
// never used.
func FuzzParseSecret(f *testing.F) {
	f.Add("KELYFOS_FUZZ_TOKEN@github.com")
	f.Add("KELYFOS_FUZZ_TOKEN@GitHub.com:bearer")
	f.Add("KELYFOS_FUZZ_TOKEN@api.github.com:basic")
	f.Add("KELYFOS_FUZZ_TOKEN@")
	f.Add("@github.com")
	f.Add("KELYFOS_FUZZ_TOKEN@a@b")
	f.Add("KELYFOS_FUZZ_TOKEN@github.com:8080")
	f.Add(":bearer")

	f.Fuzz(func(t *testing.T, spec string) {
		// One name resolves, so some inputs reach past the environment lookup
		// and exercise the half of this function that builds a Secret.
		t.Setenv("KELYFOS_FUZZ_TOKEN", "sekrit")

		s, err := ParseSecret(spec)
		if err != nil {
			return
		}
		if s.Name == "" || s.Domain == "" {
			t.Fatalf("accepted %q as a secret with name %q and domain %q", spec, s.Name, s.Domain)
		}
		if s.Domain != strings.ToLower(s.Domain) {
			t.Fatalf("domain %q is not lowercased, so binding is case-dependent", s.Domain)
		}
		if s.Scheme != "Bearer" && s.Scheme != "Basic" {
			t.Fatalf("accepted scheme %q, which is neither Bearer nor Basic", s.Scheme)
		}
		// The property that matters: a credential must match the domain it was
		// just bound to. A secret that parses and then never attaches is a
		// silent failure — the request goes out unauthenticated and the only
		// symptom is a 401 from somewhere else.
		p := &Policy{Secrets: []*Secret{s}}
		if p.secretFor(s.Domain) != s {
			t.Fatalf("a secret bound to %q does not match its own domain", s.Domain)
		}
	})
}
