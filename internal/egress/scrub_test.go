package egress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"
)

func scrubberFor(t *testing.T, values ...string) (*scrubber, *int) {
	t.Helper()
	var secrets []*Secret
	for i, v := range values {
		secrets = append(secrets, &Secret{Name: "S", Domain: "h", value: v})
		_ = i
	}
	hits := 0
	return newScrubber(secrets, func(string) { hits++ }), &hits
}

func TestAnEchoedCredentialIsReplaced(t *testing.T) {
	s, hits := scrubberFor(t, "ghp_averyrealtokenvalue")
	body := []byte(`{"error":"bad token ghp_averyrealtokenvalue","code":401}`)
	want := len(body)

	if !s.scrub(body) {
		t.Fatal("an echoed credential was not replaced")
	}
	if len(body) != want {
		t.Fatalf("the replacement changed the length from %d to %d; a keep-alive connection desyncs on that", want, len(body))
	}
	if bytes.Contains(body, []byte("ghp_")) {
		t.Errorf("the credential is still there: %s", body)
	}
	if *hits != 1 {
		t.Errorf("the record was told %d times, want exactly once per response", *hits)
	}
}

// The failure a naive scrubber has and does not report: a value split across
// two reads passes through untouched.
func TestACredentialSplitAcrossReadsIsStillCaught(t *testing.T) {
	const token = "ghp_averyrealtokenvalue"
	s, _ := scrubberFor(t, token)

	// A reader that hands over three bytes at a time, so the token straddles
	// many boundaries.
	src := io.NopCloser(iotest3{strings.NewReader("prefix " + token + " suffix")})
	out, err := io.ReadAll(s.wrap(src))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), token) {
		t.Errorf("a credential split across reads passed through: %q", out)
	}
	if got, want := len(out), len("prefix "+token+" suffix"); got != want {
		t.Errorf("stream length changed from %d to %d", want, got)
	}
	if !strings.HasPrefix(string(out), "prefix ") || !strings.HasSuffix(string(out), " suffix") {
		t.Errorf("the surrounding bytes were disturbed: %q", out)
	}
}

// iotest3 hands over at most three bytes per Read.
type iotest3 struct{ r io.Reader }

func (t iotest3) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return t.r.Read(p)
}

func TestAStreamWithNothingToScrubIsUnchanged(t *testing.T) {
	s, hits := scrubberFor(t, "ghp_averyrealtokenvalue")
	const body = "an ordinary response with no credential in it at all"
	out, err := io.ReadAll(s.wrap(io.NopCloser(strings.NewReader(body))))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != body {
		t.Errorf("an untouched stream came back different:\n got %q\nwant %q", out, body)
	}
	if *hits != 0 {
		t.Error("the record was told bytes were altered when none were")
	}
}

// A short value is not scrubbed, and the reason is that replacing it everywhere
// would corrupt far more than it protects.
func TestAShortValueIsNotScrubbed(t *testing.T) {
	if s, _ := scrubberFor(t, "abc"); s != nil {
		t.Error("a three-character value was accepted for scrubbing; every occurrence of \"abc\" in a response would be destroyed")
	}
	if s, _ := scrubberFor(t, "abcdefgh"); s == nil {
		t.Error("an eight-character value was refused; minScrub is the floor, not the bar")
	}
}

func TestNoSecretsMeansNoScrubber(t *testing.T) {
	if s := newScrubber(nil, nil); s != nil {
		t.Error("a policy with no secrets built a scrubber; a nil scrubber is the no-op path")
	}
	var nilScrubber *scrubber
	body := []byte("untouched")
	if nilScrubber.scrub(body) {
		t.Error("a nil scrubber reported a change")
	}
	if string(body) != "untouched" {
		t.Error("a nil scrubber altered bytes")
	}
}

// The scope of the de-duplication is one response, not one connection, and the
// difference is visible from outside: scrubResponse builds a scrubber — and so
// a seen map — per response, while a terminated keep-alive connection carries
// many responses through that same call. Anyone reading secret.scrubbed events
// as a per-connection count would under-read what actually came back.
func TestEachResponseThatEchoesACredentialIsReportedOnce(t *testing.T) {
	const token = "ghp_averyrealtokenvalue"
	p := &Proxy{Policy: Policy{Secrets: []*Secret{
		{Name: "GITHUB_TOKEN", Domain: "api.example.com", Scheme: "Bearer", value: token},
	}}}
	var scrubbed []string
	p.OnScrubbed = func(name, host string) { scrubbed = append(scrubbed, name+"@"+host) }

	// Within one response, forty echoes are one fact.
	echo := func() {
		t.Helper()
		resp := &http.Response{
			Header: http.Header{},
			Body:   io.NopCloser(strings.NewReader(strings.Repeat(token+" ", 40))),
		}
		p.scrubResponse(resp, "api.example.com")
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), token) {
			t.Fatalf("a credential survived the scrub: %q", out)
		}
	}

	echo()
	if len(scrubbed) != 1 {
		t.Fatalf("one response echoing the token forty times was recorded %d times, want once: %v", len(scrubbed), scrubbed)
	}

	// The next response on the same connection goes through the same call, and
	// it is a second echo rather than a repeat of the first — so it is said
	// again.
	echo()
	if len(scrubbed) != 2 {
		t.Errorf("a second response echoing the same credential was recorded %d times in total, want twice: %v", len(scrubbed), scrubbed)
	}
}

// The audit of 2026-09-01's A4/H4. A credential-bound origin that ignores the
// proxy's identity request and compresses its reply used to pass through — gzip
// of a credential does not contain the credential, so the guest decompressed
// and had the value. Now scrubResponse reports the refused encoding, the header
// echo is still scrubbed, and the caller refuses the body: nothing is
// delivered and the event records it.
func TestACompressedResponseIsRefusedAndRecorded(t *testing.T) {
	const token = "ghp_averyrealtokenvalue"
	p := &Proxy{Policy: Policy{Secrets: []*Secret{
		{Name: "GITHUB_TOKEN", Domain: "api.example.com", Scheme: "Bearer", value: token},
	}}}
	var encodings []string
	p.OnUnscrubbable = func(host, encoding string) {
		encodings = append(encodings, host+"|"+encoding)
	}

	// A gzipped body containing the credential, and the credential in a
	// plaintext header too — the header is still matchable and must still be
	// scrubbed even though the body cannot be.
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte("Bearer " + token))
	_ = w.Close()
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Encoding": []string{"gzip"},
			"X-echo":           []string{"Bearer " + token},
		},
		Body: io.NopCloser(&buf),
	}
	enc := p.scrubResponse(resp, "api.example.com")

	if enc != "gzip" {
		t.Fatalf("scrubResponse did not report the refused encoding: %q", enc)
	}
	if len(encodings) != 1 || encodings[0] != "api.example.com|gzip" {
		t.Fatalf("the compressed response was not recorded: %v", encodings)
	}
	if got := resp.Header.Get("X-echo"); strings.Contains(got, token) {
		t.Errorf("the matchable header was left holding the credential: %q", got)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("the encoding was rewritten (%q); the record names what the origin sent", resp.Header.Get("Content-Encoding"))
	}
}

// unscrubbableEncoding looks at EVERY Content-Encoding line and every
// comma-separated coding within each, case-insensitively (L12). Header.Get's
// first value only was the hole: "identity" followed by a second "gzip" line
// read as identity, and the body went through unread.
func TestEveryContentEncodingIsChecked(t *testing.T) {
	cases := []struct {
		name    string
		header  http.Header
		wantEnc string
	}{
		{"identity alone", http.Header{"Content-Encoding": {"identity"}}, ""},
		{"no header", http.Header{}, ""},
		{"whitespace around identity", http.Header{"Content-Encoding": {"  identity  "}}, ""},
		{"a second line after identity", http.Header{"Content-Encoding": {"identity", "gzip"}}, "gzip"},
		{"a comma list hiding br", http.Header{"Content-Encoding": {"identity, br"}}, "br"},
		{"uppercase is still an encoding", http.Header{"Content-Encoding": {"GZIP"}}, "GZIP"},
	}
	for _, c := range cases {
		if got := unscrubbableEncoding(c.header); got != c.wantEnc {
			t.Errorf("%s: unscrubbableEncoding = %q, want %q", c.name, got, c.wantEnc)
		}
	}
}

// A body-less response — HEAD, 204, 304, http.NoBody — leaks no credential
// however it is encoded, so scrubResponse delivers it: "" back, no event, even
// with Content-Encoding: gzip on the wire.
func TestABodylessCompressedResponseIsDelivered(t *testing.T) {
	const token = "ghp_averyrealtokenvalue"
	p := &Proxy{Policy: Policy{Secrets: []*Secret{
		{Name: "T", Domain: "api.example.com", Scheme: "Bearer", value: token},
	}}}
	events := 0
	p.OnUnscrubbable = func(string, string) { events++ }

	cases := []struct {
		name string
		resp *http.Response
	}{
		{"304", &http.Response{StatusCode: http.StatusNotModified,
			Header: http.Header{"Content-Encoding": {"gzip"}}, Body: http.NoBody}},
		{"204", &http.Response{StatusCode: http.StatusNoContent,
			Header: http.Header{"Content-Encoding": {"gzip"}}, Body: http.NoBody}},
		{"HEAD", &http.Response{StatusCode: 200, Request: &http.Request{Method: http.MethodHead},
			Header: http.Header{"Content-Encoding": {"gzip"}}, Body: io.NopCloser(strings.NewReader(""))}},
	}
	for _, c := range cases {
		if enc := p.scrubResponse(c.resp, "api.example.com"); enc != "" {
			t.Errorf("%s: a body-less response was refused with %q", c.name, enc)
		}
	}
	if events != 0 {
		t.Errorf("a body-less response fired %d unscrubbable events, want 0", events)
	}
}

// The identity request: a credential-bound leg asks the origin not to compress,
// through the production askForIdentity — the terminated leg and the plain-HTTP
// leg both call it. It goes through Policy.secretsFor, so a host with no bound
// credential is untouched and compression passes as before.
func TestACredentialBoundRequestAsksForIdentity(t *testing.T) {
	const token = "ghp_averyrealtokenvalue"
	p := &Proxy{Policy: Policy{Secrets: []*Secret{
		{Name: "GITHUB_TOKEN", Domain: "api.example.com", Scheme: "Bearer", value: token},
	}}}

	req, err := http.NewRequest("GET", "https://api.example.com/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip") // what the guest's client sent
	if bound := p.Policy.secretsFor("api.example.com"); len(bound) > 0 {
		askForIdentity(req)
	}
	if got := req.Header.Get("Accept-Encoding"); got != "identity" {
		t.Errorf("a credential-bound request still asked for %q", got)
	}

	// And an unbound host is untouched — the framing this preserves is only
	// traded away where the scrubber needs it.
	req2, err := http.NewRequest("GET", "https://unbound.example.com/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Accept-Encoding", "gzip")
	if bound := p.Policy.secretsFor("unbound.example.com"); len(bound) > 0 {
		askForIdentity(req2)
	}
	if got := req2.Header.Get("Accept-Encoding"); got != "gzip" {
		t.Errorf("an unbound host's encoding preference was overridden: %q", got)
	}
}

// Trailers are headers by another door: a chunked response's trailer values
// arrive after the body, and they used to reach the guest unexamined. The
// scrub happens at body EOF — the moment the transport fills the map in and
// the moment before resp.Write writes it.
func TestATrailersCredentialIsScrubbed(t *testing.T) {
	const token = "ghp_averyrealtokenvalue"
	p := &Proxy{Policy: Policy{Secrets: []*Secret{
		{Name: "GITHUB_TOKEN", Domain: "api.example.com", Scheme: "Bearer", value: token},
	}}}
	resp := &http.Response{
		Header:  http.Header{"Trailer": []string{"X-Auth-Note"}},
		Trailer: http.Header{},
	}
	// The transport fills resp.Trailer during the body's final read, before
	// EOF reaches the caller; simulate exactly that.
	resp.Body = &transportStyleBody{
		r:    strings.NewReader("plain body"),
		fill: func() { resp.Trailer.Set("X-Auth-Note", "Bearer "+token) },
	}
	p.scrubResponse(resp, "api.example.com")

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "plain body" {
		t.Errorf("the body was altered: %q", body)
	}
	if got := resp.Trailer.Get("X-Auth-Note"); strings.Contains(got, token) {
		t.Errorf("the trailer kept the credential: %q", got)
	}
	if got := resp.Trailer.Get("X-Auth-Note"); !strings.Contains(got, strings.Repeat("*", len(token))) {
		t.Errorf("the trailer was not scrubbed to the same length: %q", got)
	}
}

// transportStyleBody fills the response's trailer map on its final read, the
// way net/http's transport does for a chunked response with trailers.
type transportStyleBody struct {
	r    *strings.Reader
	fill func()
}

func (b *transportStyleBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err == io.EOF && b.fill != nil {
		b.fill()
	}
	return n, err
}

func (b *transportStyleBody) Close() error { return nil }
