package egress

import (
	"bufio"
	"bytes"
	"io"
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

// FuzzScrubPreservesEverythingButTheSecret is the guarantee a byte-stream
// rewriter has to make, and the reason it is fuzzed rather than argued.
//
// This code sits between an upstream server and an agent, altering bytes the
// agent is about to parse. The damage a bug does here is not a crash: it is a
// tarball that will not open or a JSON document that will not parse, with no
// symptom pointing back at the proxy. So the properties are checked directly —
// the length never changes, nothing outside a match is touched, and no bound
// value survives however it is split across reads.
func FuzzScrubPreservesEverythingButTheSecret(f *testing.F) {
	f.Add([]byte("nothing interesting here"), "ghp_averyrealtokenvalue", 7)
	f.Add([]byte("prefix ghp_averyrealtokenvalue suffix"), "ghp_averyrealtokenvalue", 3)
	f.Add([]byte("ghp_averyrealtokenvalueghp_averyrealtokenvalue"), "ghp_averyrealtokenvalue", 1)
	f.Add([]byte("aaaaaaaaaaaaaaaa"), "aaaaaaaa", 2)
	f.Add([]byte(""), "abcdefgh", 1)
	f.Add([]byte("\x00\xff\x00\xff"), "abcdefgh", 5)

	f.Fuzz(func(t *testing.T, body []byte, value string, chunk int) {
		if len(value) < minScrub || len(value) > 4096 {
			t.Skip()
		}
		if chunk < 1 || chunk > 64 {
			t.Skip()
		}
		s := newScrubber([]*Secret{{Name: "S", Domain: "h", value: value}}, nil)
		if s == nil {
			t.Fatalf("a %d-byte value built no scrubber", len(value))
		}

		src := io.NopCloser(chunked{bytes.NewReader(body), chunk})
		out, err := io.ReadAll(s.wrap(src))
		if err != nil {
			t.Fatalf("reading a scrubbed stream: %v", err)
		}

		if len(out) != len(body) {
			t.Fatalf("length changed from %d to %d; a keep-alive connection desyncs on that", len(body), len(out))
		}
		// Nothing outside a replacement may move: every byte is either what it
		// was, or the filler.
		for i := range out {
			if out[i] != body[i] && out[i] != '*' {
				t.Fatalf("byte %d became %q, which is neither the original %q nor the filler", i, out[i], body[i])
			}
		}
		// Every occurrence that was in the INPUT is gone from where it was.
		//
		// Stated against the input's positions rather than as "the value does
		// not appear in the output", which is what this assertion said first
		// and which the fuzzer correctly refuted: a value made largely of the
		// filler byte — it found "*****F*1" — can be re-created by the act of
		// replacing it, one position to the left of where the scan had reached.
		// That is an artifact of the filler, not a credential surviving, and no
		// real credential has the shape. The precise property is the one worth
		// checking, and the imprecise one was hiding it.
		v := []byte(value)
		for i := 0; i+len(v) <= len(body); {
			if !bytes.Equal(body[i:i+len(v)], v) {
				i++
				continue
			}
			for k := i; k < i+len(v); k++ {
				if out[k] != '*' {
					t.Fatalf("an occurrence at %d survived at chunk size %d: %q", i, chunk, out)
				}
			}
			i += len(v)
		}
	})
}

// chunked hands over at most n bytes per Read, so a value can be split anywhere.
type chunked struct {
	r io.Reader
	n int
}

func (c chunked) Read(p []byte) (int, error) {
	if len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}
