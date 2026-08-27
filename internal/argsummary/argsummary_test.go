package argsummary

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// Both callers' own test suites (host/servemcpaudit_test.go,
// supervisor/pluginhost_test.go) already exercise this logic in depth through
// their thin wrappers. These tests cover the same guarantees directly against
// the shared implementation, so the guarantee is checked here rather than
// only downstream of it.

func TestSummariseNeverEchoesContent(t *testing.T) {
	body := strings.Repeat("secret", 200)
	got := Summarise(json.RawMessage(`{"sandbox":"abc123","path":"/work/x","content":"` + body + `"}`))
	if strings.Contains(got, "secret") {
		t.Errorf("the record holds the file's content:\n%s", got)
	}
	for _, want := range []string{"sandbox=abc123", "path=/work/x", "content=<1200 bytes>"} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not say %q:\n%s", want, got)
		}
	}
}

// A content key is redacted for its name, not for the type the caller chose
// to put under it.
func TestContentIsSizedWhateverShapeItArrivesIn(t *testing.T) {
	body := strings.Repeat("secret", 200)
	got := Summarise(json.RawMessage(`{"content":{"smuggled":"` + body + `"}}`))
	if strings.Contains(got, "secret") {
		t.Errorf("an object under content was written into the record verbatim:\n%s", got)
	}
	if got != "content=<1215 bytes>" {
		t.Errorf("got %q, want the object recorded by its size", got)
	}
}

// Keys are sorted, so two records of the same call read the same regardless
// of Go's map iteration order.
func TestSummariseIsStable(t *testing.T) {
	raw := json.RawMessage(`{"z":1,"a":2,"m":3}`)
	first := Summarise(raw)
	if first != "a=2 m=3 z=1" {
		t.Errorf("got %q, want the keys in order", first)
	}
	for i := 0; i < 20; i++ {
		if got := Summarise(raw); got != first {
			t.Fatalf("the same call rendered two ways: %q then %q", first, got)
		}
	}
}

// Malformed arguments are a fact about the call, and the call is still
// recorded.
func TestSummariseSurvivesGarbage(t *testing.T) {
	got := Summarise(json.RawMessage(`{"unclosed":`))
	if !strings.Contains(got, "unparseable") {
		t.Errorf("garbage arguments were not reported as such: %q", got)
	}
}

// No one argument — an object, an array, or the joined line itself — can
// grow a record line past what its readers can read back.
func TestNoOneArgumentCanFillTheLine(t *testing.T) {
	got := Summarise(json.RawMessage(`{"x":{"a":"` + strings.Repeat("A", 300) + `"}}`))
	if strings.Count(got, "A") > MaxArgBytes {
		t.Errorf("an object argument was written out whole:\n%s", got)
	}
	if !strings.Contains(got, "(308 bytes)") {
		t.Errorf("the truncated object does not say what it was cut from:\n%s", got)
	}

	elems := make([]string, 2000)
	for i := range elems {
		elems[i] = `"a"`
	}
	got = Summarise(json.RawMessage(`{"argv":[` + strings.Join(elems, ",") + `]}`))
	if len(got) > MaxArrayBytes+64 {
		t.Errorf("a 2000-element array rendered %d characters, which is not a log line:\n%s", len(got), got)
	}
	if !strings.Contains(got, "more)") {
		t.Errorf("the array does not say how many elements it left out:\n%s", got)
	}

	// The case the budget exists for: a real allowlist survives whole.
	allow := `{"allow":["registry.npmjs.org","github.com","objects.githubusercontent.com",` +
		`"proxy.golang.org","sum.golang.org","pypi.org","files.pythonhosted.org","deb.debian.org"]}`
	if got := Summarise(json.RawMessage(allow)); strings.Contains(got, "more)") {
		t.Errorf("an eight-domain allowlist was cut short:\n%s", got)
	} else if !strings.Contains(got, "deb.debian.org") {
		t.Errorf("the allowlist lost its last entry:\n%s", got)
	}
}

// Nothing bounds how many arguments a call has, so the joined line needs its
// own bound.
func TestTheWholeSummaryStaysALine(t *testing.T) {
	parts := make([]string, 2000)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"k%04d":"v"`, i)
	}
	got := Summarise(json.RawMessage("{" + strings.Join(parts, ",") + "}"))
	if len(got) > MaxArgsBytes+64 {
		t.Errorf("2000 arguments rendered %d characters", len(got))
	}
	if !strings.Contains(got, "bytes)") {
		t.Errorf("the clipped summary does not say how long the whole thing was:\n%.200s…", got)
	}
}

// Clipping happens on a rune boundary, never leaving half a multi-byte
// character in a string that gets marshalled and printed.
func TestClipUTF8NeverLeavesHalfARune(t *testing.T) {
	s := strings.Repeat("€", 10) // three bytes each
	for n := 0; n <= len(s); n++ {
		got := ClipUTF8(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("clipping %d bytes of a multi-byte string left %q, which is not valid UTF-8", n, got)
		}
		if len(got) > n {
			t.Fatalf("clipping to %d bytes returned %d", n, len(got))
		}
	}
	if got := ClipUTF8("ab�cd", 5); got != "ab�" {
		t.Errorf("got %q, want the replacement character kept", got)
	}
}

// A record line is a line: a summary must never contain a raw newline that
// would let a caller forge an extra entry in anything that reads the
// transcript by line.
func TestSummariseNeverProducesAMultilineString(t *testing.T) {
	for _, raw := range []string{
		`{}`, `{"cmd":"ls","content":"abc"}`, `{"a":[1,2,{"b":null}],"c":{"d":"e"}}`,
		`not json at all`, `{"content":12345}`, `[1,2,3]`, ``, "{\"\\n\":0}",
	} {
		out := Summarise(json.RawMessage(raw))
		if strings.ContainsAny(out, "\n\r") {
			t.Fatalf("Summarise produced a multi-line summary from %q:\n%q", raw, out)
		}
	}
}
