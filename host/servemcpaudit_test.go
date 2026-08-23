package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The audit lane's whole value is that it holds what a reader wants and not
// what it must never hold. Both halves are checkable without a machine.

// Content never enters the record. The rule is file.write's, applied to every
// argument on every tool — including ones that do not exist yet, because the
// summariser walks what it is given rather than knowing the tools.
func TestArgumentSummaryNeverCarriesContent(t *testing.T) {
	body := strings.Repeat("secret", 200)
	got := summariseArgs(json.RawMessage(`{"sandbox":"abc123","path":"/work/x","content":"` + body + `"}`))
	if strings.Contains(got, "secret") {
		t.Errorf("the record holds the file's content:\n%s", got)
	}
	for _, want := range []string{"sandbox=abc123", "path=/work/x", "content=<1200 bytes>"} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not say %q:\n%s", want, got)
		}
	}

	// stdin is the same kind of thing on a different tool.
	got = summariseArgs(json.RawMessage(`{"sandbox":"a","command":"cat","stdin":"hunter2"}`))
	if strings.Contains(got, "hunter2") {
		t.Errorf("the record holds what was typed into a command:\n%s", got)
	}
	if !strings.Contains(got, "stdin=<7 bytes>") {
		t.Errorf("the summary does not size the stdin it withheld:\n%s", got)
	}
}

// An argument nobody wrote a rule for still appears, because a log that only
// shows the arguments someone remembered is a log that hides the new one.
func TestArgumentSummaryShowsWhatItDoesNotKnow(t *testing.T) {
	got := summariseArgs(json.RawMessage(`{"count":3,"allow":["a.example","b.example"],"deep":{"x":1}}`))
	for _, want := range []string{"count=3", "allow=[a.example,b.example]", `deep={"x":1}`} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not say %q:\n%s", want, got)
		}
	}
}

// Keys are sorted, so two records of the same call read the same. Go's map
// iteration would otherwise make the transcript's wording depend on nothing.
func TestArgumentSummaryIsStable(t *testing.T) {
	raw := json.RawMessage(`{"z":1,"a":2,"m":3}`)
	first := summariseArgs(raw)
	if first != "a=2 m=3 z=1" {
		t.Errorf("got %q, want the keys in order", first)
	}
	for i := 0; i < 20; i++ {
		if got := summariseArgs(raw); got != first {
			t.Fatalf("the same call rendered two ways: %q then %q", first, got)
		}
	}
}

// A long argument is truncated and says what it was cut from, so a line stays a
// line without the record quietly claiming the value was short.
func TestArgumentSummaryTruncatesHonestly(t *testing.T) {
	got := summariseArgs(json.RawMessage(`{"path":"` + strings.Repeat("d/", 200) + `"}`))
	if !strings.Contains(got, "(400 bytes)") {
		t.Errorf("the truncation does not name the full length:\n%s", got)
	}
	if len(got) > 200 {
		t.Errorf("the summary is %d characters, which is not a log line", len(got))
	}
}

// Malformed arguments are a fact about the call, and the call is still recorded.
func TestArgumentSummarySurvivesGarbage(t *testing.T) {
	got := summariseArgs(json.RawMessage(`{"unclosed":`))
	if !strings.Contains(got, "unparseable") {
		t.Errorf("garbage arguments were not reported as such: %q", got)
	}
}

// Every tool call goes through one function, so no tool can be added that skips
// the record. Reading the source is the check: the alternative is trusting that
// whoever adds the next tool remembers.
func TestEveryToolCallPassesTheAudit(t *testing.T) {
	src := readSource(t, "servemcp.go")
	i := strings.Index(src, "func (s *hostServer) callTool(")
	if i < 0 {
		t.Fatal("callTool is gone; this test needs rewriting with it")
	}
	body := src[i:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "s.auditCall(p)") {
		t.Error("callTool does not audit; a tool call that is not recorded is a door with no record")
	}
	if !strings.Contains(body, "s.dispatchTool(p)") {
		t.Error("callTool no longer dispatches through one place")
	}
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
