package proto

import (
	"strings"
	"testing"
)

// P7-17/F20, rider 1 (from the record workstream's review).
//
// internal/recorder/erase.go exempts Error.Kind from erasure as "a fixed
// enumeration". It was not one: host/exec.go copied resp.Error.Kind verbatim
// off the wire and nothing on the host checked it against the seven constants
// below — exitCodeFor switches with a default, which accepts rather than
// rejects. So arbitrary guest text sat in a field docs/retention.md promises
// "survives unchanged", and survived an erasure verbatim.
//
// That is F12's exact shape one field to the left: an exemption justified by a
// property no code enforced. The enumeration lives here, so the validator does
// too, and it runs at the same edge every other guest string is cleaned at.

func TestErrorKindIsAnEnumerationOnIngest(t *testing.T) {
	known := []string{ErrBadRequest, ErrNotFound, ErrDenied, ErrTimeout, ErrKilled, ErrIO, ErrInternal}
	for _, k := range known {
		var e Error
		readOne(t, `{"kind":"`+k+`","message":"why"}`, &e)
		if e.Kind != k {
			t.Errorf("a known kind %q was rewritten to %q", k, e.Kind)
		}
		if e.Message != "why" {
			t.Errorf("a known kind's message was altered: %q", e.Message)
		}
	}

	for _, k := range []string{
		"",
		"tool",
		"Denied",                    // case matters: the enumeration is exact
		"denied ",                   // and so does whitespace
		"cat: /etc/shadow: no such", // guest stdout, which is F12's own shape
		strings.Repeat("a", 4096),   // unbounded, which the record field is not
		"\x1b[2Jdenied",             // and the F20 shape on top of it
		"‮deined",                   // and the F1 shape
	} {
		var e Error
		readOne(t, `{"kind":`+mustQuote(t, k)+`,"message":"why"}`, &e)
		if e.Kind != ErrInternal {
			t.Errorf("an unknown kind %q came back as %q, want %q", k, e.Kind, ErrInternal)
		}
		if hasRawControl(e.Kind) {
			t.Errorf("an unknown kind left a raw control byte in the field: %q", e.Kind)
		}
	}
}

// The rejected kind is not simply thrown away: it moves into the message,
// which is where guest-chosen prose belongs and is a field the record no longer
// carries from this path at all. So an operator still sees what the guest said,
// on their terminal, and the chain still carries only an enumeration.
func TestAnUnknownErrorKindSurvivesInTheMessage(t *testing.T) {
	var e Error
	readOne(t, `{"kind":"executable_not_found","message":"/tmp/x"}`, &e)
	if e.Kind != ErrInternal {
		t.Fatalf("kind = %q", e.Kind)
	}
	if !strings.Contains(e.Message, "executable_not_found") {
		t.Errorf("the guest's own kind was lost entirely: %q", e.Message)
	}
	if !strings.Contains(e.Message, "/tmp/x") {
		t.Errorf("the guest's own message was lost: %q", e.Message)
	}
	// An empty kind adds nothing to say, so it says nothing.
	var empty Error
	readOne(t, `{"message":"plain"}`, &empty)
	if empty.Message != "plain" {
		t.Errorf("an empty kind was folded into the message anyway: %q", empty.Message)
	}
}

// KnownErrorKind is the enumeration itself, and the constants are what it is
// built from — compared against the list rather than a restatement of it, so a
// constant added without a row here fails rather than silently becoming
// "internal".
func TestKnownErrorKindCoversEveryConstant(t *testing.T) {
	for _, k := range []string{ErrBadRequest, ErrNotFound, ErrDenied, ErrTimeout, ErrKilled, ErrIO, ErrInternal} {
		if !KnownErrorKind(k) {
			t.Errorf("KnownErrorKind(%q) is false for one of this package's own constants", k)
		}
	}
	if KnownErrorKind("") || KnownErrorKind("tool") {
		t.Error("KnownErrorKind accepted something that is not one of the constants")
	}
}

func mustQuote(t *testing.T, s string) string {
	t.Helper()
	q, err := marshalString(s)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
