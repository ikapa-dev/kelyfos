package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// P7-17/F20, second review round: the sweep that does not depend on anybody
// remembering a field.
//
// The hand-written table in log_test.go listed the fields somebody thought of.
// It missed `session.start`'s image, arch and kelyfos — printed raw two lines
// under a Reason that was SafeText'd and four lines above a ready line that
// gained SafeText in the very commit that added the table — and it missed
// `team.message`'s kind. `kelyfos watch` was clean for the same event, because
// its own code was written later and by hand. That is the whole failure mode
// this finding is about, reproduced inside the test written to catch it.
//
// So this enumerates: every event type the renderers switch on, every string
// field on recorder.Event, one at a time, through all three surfaces. A field
// added to Event later is covered without anybody adding a row.

// everyEventType is the switch's own vocabulary. A type missing here is only a
// gap in coverage, never a false pass, and TestSweepCoversEveryRenderedType
// below checks the list against the renderers' own source.
func everyEventType() []string {
	return []string{
		recorder.TypeSessionStart, recorder.TypeSessionReady, recorder.TypeSessionEnd,
		recorder.TypeCommandStart, recorder.TypeCommandOutput, recorder.TypeCommandExit,
		recorder.TypeFileWrite, recorder.TypeEgressAttempt,
		recorder.TypeSecretUse, recorder.TypeSecretWithheld, recorder.TypeSecretScrubbed,
		recorder.TypeResourceOOM, recorder.TypeResourceTimeout, recorder.TypeResourceSummary,
		recorder.TypeTeamMessage, recorder.TypeTeamRefused, recorder.TypeTeamStore,
		recorder.TypeTeamSpawn, recorder.TypeMCPHostCall, recorder.TypeMCPHostResult,
		recorder.TypePluginCall, recorder.TypePluginCrash,
		recorder.TypeSessionPause, recorder.TypeSessionResume, recorder.TypeRunReview,
		recorder.TypeShellStart, recorder.TypeShellEnd, recorder.TypeForwardAccept,
		// The five that had no renderer until the arms were added: they were
		// printed as a raw JSON line, so the sweep had nothing to sweep and
		// this list had nothing to name. secret.withheld and secret.scrubbed
		// were already here, which is why only three arrive now.
		recorder.TypeSessionPolicy, recorder.TypeTeamTopology, recorder.TypeSessionErasure,
		// channel.refused (audit 2026-09-01, A2/A3): its Reason is host text,
		// but the sweep's job is that nobody decides by hand what gets
		// checked — it is swept like every other arm.
		recorder.TypeChannelRefused,
	}
}

// stringFields is every settable string field on recorder.Event, by name.
// Reflection rather than a list, which is the point.
func stringFields(t *testing.T) []string {
	t.Helper()
	rt := reflect.TypeOf(recorder.Event{})
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() || f.Type.Kind() != reflect.String {
			continue
		}
		switch f.Name {
		case "Type", "TS", "Prev", "Hash":
			// Type selects the branch, TS is sliced as a timestamp, and Prev
			// and Hash are host-computed digests that never carry guest text.
			continue
		case "Data":
			// base64 on the wire, decoded by the renderer and handled by
			// SafeBody, which TestF20_TheReplayKeepsColouredOutputButRefusesOSC
			// covers with real escape sequences rather than a marker byte.
			continue
		}
		out = append(out, f.Name)
	}
	if len(out) < 20 {
		t.Fatalf("only %d string fields found on recorder.Event; the reflection is wrong", len(out))
	}
	return out
}

const sweepHostile = "\x1b[2J\x1b[3Jpwned\rlooking"

func eventWith(evType, field string) recorder.Event {
	e := recorder.Event{Type: evType, TS: "2026-08-29T10:00:00.000Z"}
	reflect.ValueOf(&e).Elem().FieldByName(field).SetString(sweepHostile)
	return e
}

func TestTheReplayEscapesEveryStringFieldOfEveryEvent(t *testing.T) {
	for _, evType := range everyEventType() {
		for _, field := range stringFields(t) {
			line := renderEvent(t, eventWith(evType, field))
			if f20Unsafe(line) {
				t.Errorf("%s.%s reached kelyfos log raw:\n  %q", evType, field, line)
			}
		}
	}
}

func TestTheViewerEscapesEveryStringFieldOfEveryEvent(t *testing.T) {
	for _, evType := range everyEventType() {
		for _, field := range stringFields(t) {
			if got := viewLogLine(eventWith(evType, field)); f20Unsafe(got) {
				t.Errorf("%s.%s reached kelyfos view raw:\n  %q", evType, field, got)
			}
		}
	}
}

func TestTheWatchTUIEscapesEveryStringFieldOfEveryEvent(t *testing.T) {
	for _, evType := range everyEventType() {
		for _, field := range stringFields(t) {
			m := &watchModel{session: "s1"}
			m.absorb(eventWith(evType, field))
			if got := f20WatchLines(m); f20UnsafeStyled(got) {
				t.Errorf("%s.%s reached kelyfos watch raw:\n  %q", evType, field, got)
			}
		}
	}
}

// The list above is coverage, so it has to keep up with the switch it mirrors.
// Every recorder.Type* constant the replay names in its own source must be in
// it — which is how session.start would have been caught the first time.
func TestSweepCoversEveryRenderedType(t *testing.T) {
	src, err := sweepSource("log.go")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, ty := range everyEventType() {
		listed[ty] = true
	}
	// recorder.TypeX in a `case` line of printEvent's switch.
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "case recorder.Type") {
			continue
		}
		for _, part := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(trimmed, "case "), ":"), ",") {
			name := strings.TrimSpace(part)
			val, ok := typeConstValue(name)
			if !ok {
				t.Errorf("printEvent switches on %s, which this test cannot resolve", name)
				continue
			}
			if !listed[val] {
				t.Errorf("printEvent renders %s (%q) and the sweep does not cover it.\n"+
					"  Add it to everyEventType() — an unrendered type is a field nobody checked.",
					name, val)
			}
		}
	}
}

// safeEvent takes a value and must behave like it: a value copy shares its
// slices' backing arrays, so rewriting through the copy reached into the
// caller's own Cmd and Allow. Nothing depended on it — all three callers use
// only the result — but a signature that says "value in, value out" has to
// mean it (P7-17/F20, folded into F13(b)).
func TestSafeEventDoesNotReachIntoItsCallersSlices(t *testing.T) {
	orig := recorder.Event{
		Type: recorder.TypeCommandStart,
		TS:   "2026-08-29T10:00:00.000Z",
		Cmd:  []string{sweepHostile, "plain"},
	}
	before := orig.Cmd[0]

	got := safeEvent(orig)

	if orig.Cmd[0] != before {
		t.Errorf("safeEvent rewrote the caller's slice element:\n  was %q\n  now %q", before, orig.Cmd[0])
	}
	if got.Cmd[0] == before {
		t.Errorf("safeEvent returned the hostile value unchanged: %q", got.Cmd[0])
	}
	if got.Cmd[1] != "plain" {
		t.Errorf("safeEvent altered a clean element: %q", got.Cmd[1])
	}
}
