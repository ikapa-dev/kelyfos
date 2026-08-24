package egress

import (
	"bytes"
	"io"
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
		t.Errorf("the record was told %d times, want exactly once per connection", *hits)
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
