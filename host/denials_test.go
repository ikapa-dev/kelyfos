package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/egress"
)

// The host prints a refusal the guest's client may never show, and prints it
// once: a program that retries in a loop is one thing to fix, not forty.
func TestBlockedIsAnnouncedOnceWithItsFix(t *testing.T) {
	var out strings.Builder
	b := newBlockedOnce(&out)
	for i := 0; i < 5; i++ {
		b.say(egress.Attempt{Host: "api.stripe.com", Port: 443, Reason: egress.ReasonNotAllowed})
	}
	got := out.String()
	if n := strings.Count(got, "[egress.host]"); n != 1 {
		t.Errorf("five identical refusals printed %d times:\n%s", n, got)
	}
	if !strings.Contains(got, `add allow = ["api.stripe.com"]`) {
		t.Errorf("no fix line:\n%s", got)
	}

	// The same host on another port needs the same line added to the same
	// file, so it is not said again.
	b.say(egress.Attempt{Host: "api.stripe.com", Port: 80, Reason: egress.ReasonNotAllowed})
	if n := strings.Count(out.String(), "[egress.host]"); n != 1 {
		t.Errorf("the same advice was printed %d times:\n%s", n, out.String())
	}

	// A different host is a different thing to fix, so it is said.
	b.say(egress.Attempt{Host: "example.net", Port: 443, Reason: egress.ReasonNotAllowed})
	if !strings.Contains(out.String(), "example.net") {
		t.Errorf("a second host was swallowed:\n%s", out.String())
	}
}

// What is not a refusal is not announced. An allowed request is ordinary, and a
// dial that failed has no fix line — a line here would teach the reader to skim
// past the ones that do.
func TestOnlyRefusalsAreAnnounced(t *testing.T) {
	for _, a := range []egress.Attempt{
		{Host: "github.com", Port: 443, Allowed: true},
		{Host: "github.com", Port: 443, Reason: egress.ReasonDialFailed},
		{Host: "github.com", Port: 443, Reason: egress.ReasonBadRequest},
	} {
		var out strings.Builder
		newBlockedOnce(&out).say(a)
		if out.String() != "" {
			t.Errorf("%+v was announced as a refusal:\n%s", a, out.String())
		}
	}
}

// A permitted domain on a port the proxy does not carry is its own refusal,
// with its own fix.
func TestBlockedPortIsItsOwnRefusal(t *testing.T) {
	var out strings.Builder
	newBlockedOnce(&out).say(egress.Attempt{
		Host: "example.com", Port: 8080, Reason: egress.ReasonBadPort})
	got := out.String()
	if !strings.Contains(got, "[egress.port]") || !strings.Contains(got, "8080") {
		t.Errorf("the port refusal is not what was printed:\n%s", got)
	}
}

// A guest that floods the proxy with distinct disallowed hostnames must not
// grow this map — or the lines printed for it — without limit (S5a).
func TestBlockedOnceCapsHowManyDistinctDenialsItRemembers(t *testing.T) {
	var out strings.Builder
	b := newBlockedOnce(&out)
	for i := 0; i < maxBlockedEntries+200; i++ {
		b.say(egress.Attempt{Host: fmt.Sprintf("host-%d.example", i), Port: 443, Reason: egress.ReasonNotAllowed})
	}
	if len(b.seen) > maxBlockedEntries {
		t.Errorf("seen grew to %d entries, want at most %d", len(b.seen), maxBlockedEntries)
	}

	// An ordinary run — a handful of distinct hosts, nowhere near the cap —
	// must keep deduplicating exactly as before: a host seen before the cap
	// was reached still prints nothing the second time.
	before := out.Len()
	b.say(egress.Attempt{Host: "host-0.example", Port: 443, Reason: egress.ReasonNotAllowed})
	if out.Len() != before {
		t.Error("a host seen before the cap was reached printed again")
	}
}

// What a "run finished" notification says. Somebody who walked away wants the
// two facts the shell would have given them: whether it worked, and how long.
func TestFinishedBodySaysWhatHappened(t *testing.T) {
	zero, three := 0, 3
	for _, tc := range []struct {
		reason string
		code   *int
		took   time.Duration
		want   string
	}{
		{"command_exited", &zero, 4 * time.Second, "finished cleanly after 4s"},
		{"command_exited", &three, 90 * time.Second, "exited 3 after 1m30s"},
		{"timeout", nil, 30 * time.Minute, "timed out after 30m0s"},
		{"interrupted", nil, 12 * time.Second, "stopped after 12s"},
		{"vm_exited", nil, 2 * time.Second, "the sandbox died unexpectedly after 2s"},
		{"shutdown", nil, 700 * time.Millisecond, "shutdown after 700ms"},
	} {
		if got := finishedBody(tc.reason, tc.code, tc.took); got != tc.want {
			t.Errorf("%s/%v -> %q, want %q", tc.reason, tc.code, got, tc.want)
		}
	}
}
