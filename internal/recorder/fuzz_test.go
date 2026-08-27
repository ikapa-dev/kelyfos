package recorder

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Fuzz targets for the flight recorder (P6-3).
//
// The chain is hostile input by two separate routes, and the second is the one
// that matters. The first is ordinary: the file was written by an earlier run,
// and a run can end badly. The second arrives with P6-6 — an exported session
// report is a file a stranger hands you and asks you to believe, and
// `kelyfos verify` will run exactly this code over exactly those bytes. A
// parser that can be made to crash is a denial of the audit story; a parser
// that can be made to *agree* with a forged chain is worse.

// FuzzVerifyAgreesWithRead asserts the property the product depends on rather
// than merely the absence of a panic.
//
// Verify and Read parse the same format for different purposes: one checks the
// chain, the other renders it. If Verify accepts a file, Read must agree about
// what is in it — same count, no error. A divergence means the verified thing
// and the displayed thing are not the same thing, which is precisely the gap a
// forged report would live in.
func FuzzVerifyAgreesWithRead(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(`{"seq":1,"type":"session.start"}` + "\n"))
	f.Add([]byte("not json\n"))
	f.Add([]byte(`{"seq":1,"prev":"","hash":"deadbeef","type":"session.start"}` + "\n"))
	f.Add([]byte(`{"v":1,"seq":1,"ts":"","sandbox":"","type":"session.start","source":"host","prev":"","hash":""}` + "\n"))
	f.Add([]byte(`{"seq":2,"type":"session.end"}` + "\n"))
	f.Add([]byte(`{"seq":1,"type":"session.start"}` + "\n" + `{"seq":2,"type":"session.end"}` + "\n"))
	f.Add(validChain(f, 3))

	f.Fuzz(func(t *testing.T, data []byte) {
		n, _, verr := Verify(bytes.NewReader(data))
		if verr != nil {
			// A refusal is a correct outcome. Verify's own count is a prefix
			// length and is not required to mean anything once it has failed.
			return
		}
		events, rerr := Read(bytes.NewReader(data))
		if rerr != nil {
			t.Fatalf("Verify accepted %d events but Read refused the same bytes: %v", n, rerr)
		}
		if len(events) != n {
			t.Fatalf("Verify counted %d events and Read found %d in the same bytes", n, len(events))
		}
	})
}

// FuzzAppendFieldValues drives Append with fuzzer-chosen FIELD VALUES, rather
// than fuzzer-chosen file bytes — the class FuzzVerifyAgreesWithRead above
// cannot see, because it fuzzes an already-serialized chain and never asks
// what happens when Append itself is handed a value too large to write back
// out (S1). internal/egress's CONNECT host and host/mcpobserve.go's exec
// output were two callers that could do exactly that, and Append had no guard
// of its own against either.
//
// The property: for any string a caller puts in an event's guest-influenced
// fields, appending it must never leave a session whose Verify and Read
// disagree, and Verify must see every event this test believes it appended —
// "believes," because Append is allowed to refuse a field it truly cannot
// bring under MaxLine (fitUnderMaxLine's maxClipAttempts bound), just never by
// writing a line no reader can get past.
//
// F8: an oversized value in a field clipLargestField could not see (it named
// six fields by hand; EvError.Message was not one of them) made Append fail
// closed instead of clipping, so the event vanished from the record rather
// than being kept in truncated form — the same failure mode as the bug this
// fuzz target was originally written for, just reached through a different
// field. The middle event below now goes through setAllStringFields, which
// sets *every* string field this test can reach on Event — including
// EvError.Message and .Kind — to the fuzzed value, rather than naming Data and
// Host by hand the way this target used to. A field added to Event later that
// clipLargestField fails to cover will make this event's Append behave
// differently from the six original fields (or, if it is not even reachable
// by fitUnderMaxLine's own reflection, fail identically to how F8's bug
// behaved), and either way the round-trip checks below catch it without
// anyone having to read clipLargestField to notice.
func FuzzAppendFieldValues(f *testing.F) {
	f.Add("", "")
	f.Add("short output", "github.com")
	f.Add(strings.Repeat("a", 1<<10), "")
	f.Add(strings.Repeat("x", 20<<20), strings.Repeat("y", 1<<20))
	f.Add(string([]byte{0xff, 0xfe, 0x00, 0x80}), "")
	f.Add(strings.Repeat("é", 5<<20), strings.Repeat("日", 5<<20))
	f.Add(strings.Repeat("m", 9<<20), "")

	f.Fuzz(func(t *testing.T, data, host string) {
		root := t.TempDir()
		rec, err := Open(root, "fuzzappend")
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		everyField := Event{Bytes: len(data)}
		setAllStringFields(&everyField, data)
		everyField.Type = TypeCommandOutput
		// Bracketed by two ordinary events, so a gap left by a refused event in
		// the middle — the bug this fuzz target is really aimed at — shows up as
		// a broken chain rather than merely a short one.
		_ = rec.Append(Event{Type: TypeSessionStart})
		_ = rec.Append(everyField)
		_ = rec.Append(Event{Type: TypeEgressAttempt, Host: host})
		_ = rec.Append(Event{Type: TypeSessionEnd})
		if err := rec.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}

		blob, err := os.ReadFile(Path(root, "fuzzappend"))
		if err != nil {
			t.Fatalf("reading the chain back: %v", err)
		}
		for i, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
			if len(line) > MaxLine {
				t.Fatalf("line %d is %d bytes, over MaxLine (%d) — Append wrote something no reader can read back",
					i+1, len(line), MaxLine)
			}
		}
		n, _, verr := Verify(bytes.NewReader(blob))
		if verr != nil {
			t.Fatalf("append-then-verify must round-trip for any field value, but Verify failed: %v", verr)
		}
		events, rerr := Read(bytes.NewReader(blob))
		if rerr != nil {
			t.Fatalf("Verify accepted the chain but Read refused the same bytes: %v", rerr)
		}
		if len(events) != n {
			t.Fatalf("Verify counted %d events and Read found %d in the same chain", n, len(events))
		}
	})
}

// validChain builds a real chain so the corpus contains at least one input that
// reaches past the first hash check. A seed that always fails at line one
// teaches the fuzzer nothing about the interesting half of the function.
//
// It goes through the real Recorder rather than hand-rolling the chaining. A
// hand-built seed would encode this test's belief about how events are stamped,
// and if that belief drifted from Append the seed would quietly stop being a
// valid chain — which is the one property it exists to have.
func validChain(f *testing.F, n int) []byte {
	f.Helper()
	root := f.TempDir()
	rec, err := Open(root, "fuzzseed")
	if err != nil {
		f.Fatalf("opening the seed recorder: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := rec.Append(Event{Type: TypeSessionStart}); err != nil {
			f.Fatalf("building the seed chain: %v", err)
		}
	}
	if err := rec.Close(); err != nil {
		f.Fatalf("closing the seed recorder: %v", err)
	}
	blob, err := os.ReadFile(Path(root, "fuzzseed"))
	if err != nil {
		f.Fatalf("reading the seed chain back: %v", err)
	}
	if _, _, err := Verify(bytes.NewReader(blob)); err != nil {
		f.Fatalf("the seed chain this test built does not verify: %v", err)
	}
	return blob
}

// setAllStringFields sets every string field reachable from e — its own
// top-level fields, plus the fields of any pointed-to struct such as *EvError
// — to s, allocating the pointed-to struct first if it is nil.
//
// It walks the struct the same way largestStringField in recorder.go does,
// deliberately by a second, independent reflect.Value walk rather than by
// calling into that function: the point of FuzzAppendFieldValues is to catch
// a future field clipLargestField's walk fails to reach, and a test that
// reused clipLargestField's own traversal to build its input could never
// observe that kind of gap — whatever the production walk missed, this one
// would miss identically, for the same reason.
func setAllStringFields(e *Event, s string) {
	v := reflect.ValueOf(e).Elem()
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(s)
		case reflect.Ptr:
			if fv.Type().Elem().Kind() != reflect.Struct {
				continue
			}
			if fv.IsNil() {
				fv.Set(reflect.New(fv.Type().Elem()))
			}
			sv := fv.Elem()
			for j := 0; j < sv.NumField(); j++ {
				if sfv := sv.Field(j); sfv.Kind() == reflect.String {
					sfv.SetString(s)
				}
			}
		}
	}
}

// TestAppendClipsOversizedEvErrorMessage is F8's direct repro: an oversized
// EvError.Message used to be invisible to clipLargestField, which named six
// fields by hand and did not include it, so fitUnderMaxLine's clip loop found
// nothing to clip, exhausted maxClipAttempts, and Append refused the whole
// event — an oversized error message made the event carrying it vanish from
// the record instead of being clipped and kept, exactly like an oversized
// Data or Host used to before S1 closed those two doors.
//
// 9<<20 bytes matches the finding: comfortably past MaxLine (8<<20) on its
// own, so no other field needs to contribute for the bug to reproduce.
func TestAppendClipsOversizedEvErrorMessage(t *testing.T) {
	root := t.TempDir()
	rec, err := Open(root, "f8")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	oversized := strings.Repeat("m", 9<<20)
	if err := rec.Append(Event{
		Type:  TypeCommandExit,
		Error: &EvError{Kind: "oom", Message: oversized},
	}); err != nil {
		t.Fatalf("Append refused an event whose only oversized field was EvError.Message: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	blob, err := os.ReadFile(Path(root, "f8"))
	if err != nil {
		t.Fatalf("reading the chain back: %v", err)
	}
	events, rerr := Read(bytes.NewReader(blob))
	if rerr != nil {
		t.Fatalf("reading back the appended event: %v", rerr)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event recorded, got %d — the oversized EvError.Message must not make the event vanish", len(events))
	}
	got := events[0]
	if got.Error == nil {
		t.Fatalf("event was recorded but its Error field is gone entirely")
	}
	if got.Error.Kind != "oom" {
		t.Fatalf("EvError.Kind = %q, want %q — clipping the message must not disturb an unrelated field", got.Error.Kind, "oom")
	}
	if len(got.Error.Message) >= len(oversized) {
		t.Fatalf("EvError.Message is %d bytes, want it clipped below the original %d", len(got.Error.Message), len(oversized))
	}
	if !strings.Contains(got.Error.Message, "clipped from") {
		t.Fatalf("EvError.Message = %q, want it to carry the clip note fitUnderMaxLine's other clipped fields carry", got.Error.Message)
	}

	if _, _, verr := Verify(bytes.NewReader(blob)); verr != nil {
		t.Fatalf("clipped event does not verify: %v", verr)
	}
}

// TestAppendClipsEverySessionPolicySlice is F8's fixture repeated for P7-2's
// six new slice fields, named in docs/policy-record.md §9.1 as the ones the
// same reflection gap misses: Allow, Secrets, Plugins, Forwards and Tools are
// []string or []EvSecret, invisible to largestStringField the way Cmd always
// was; Ports is []int and gets its own dedicated clip rather than a string
// substitution. Each case is oversized on its own — nothing else on the event
// contributes — so the event vanishing here would be this field's clip
// missing, not some other field masking it.
//
// Tools was the field this test did not cover on P7-2's first pass — the
// review that reopened P7-2 (F1) proved with this exact fixture shape that an
// oversized Tools value made the whole event vanish, since clipLargestField's
// list named the other five and stopped one short. Its subtest below is that
// proof kept as a regression test, and TestClipLargestFieldCoversEverySliceField
// further down backstops the whole list by construction so a seventh miss
// cannot happen silently.
func TestAppendClipsEverySessionPolicySlice(t *testing.T) {
	longStrings := func(n, each int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("d", each)
		}
		return out
	}
	longPorts := func(n int) []int {
		out := make([]int, n)
		for i := range out {
			out[i] = 10000 + i
		}
		return out
	}

	cases := []struct {
		name  string
		build func(e *Event)
		check func(t *testing.T, e Event)
	}{
		{"Allow", func(e *Event) { e.Allow = longStrings(1000, 10<<10) },
			func(t *testing.T, e Event) {
				if len(e.Allow) != 1 || !strings.Contains(e.Allow[0], "clipped from") {
					t.Fatalf("Allow = %v, want one element noting a clip", e.Allow)
				}
			}},
		{"Plugins", func(e *Event) { e.Plugins = longStrings(1000, 10<<10) },
			func(t *testing.T, e Event) {
				if len(e.Plugins) != 1 || !strings.Contains(e.Plugins[0], "clipped from") {
					t.Fatalf("Plugins = %v, want one element noting a clip", e.Plugins)
				}
			}},
		{"Forwards", func(e *Event) { e.Forwards = longStrings(1000, 10<<10) },
			func(t *testing.T, e Event) {
				if len(e.Forwards) != 1 || !strings.Contains(e.Forwards[0], "clipped from") {
					t.Fatalf("Forwards = %v, want one element noting a clip", e.Forwards)
				}
			}},
		{"Secrets", func(e *Event) {
			s := make([]EvSecret, 2000)
			for i := range s {
				s[i] = EvSecret{Name: strings.Repeat("n", 5000), Host: strings.Repeat("h", 5000)}
			}
			e.Secrets = s
		}, func(t *testing.T, e Event) {
			if len(e.Secrets) != 1 || !strings.Contains(e.Secrets[0].Name, "clipped from") {
				t.Fatalf("Secrets = %v, want one entry noting a clip", e.Secrets)
			}
		}},
		{"Tools", func(e *Event) { e.Tools = longStrings(1000, 10<<10) },
			func(t *testing.T, e Event) {
				if len(e.Tools) != 1 || !strings.Contains(e.Tools[0], "clipped from") {
					t.Fatalf("Tools = %v, want one element noting a clip", e.Tools)
				}
			}},
		{"Ports", func(e *Event) { e.Ports = longPorts(3 << 20) },
			func(t *testing.T, e Event) {
				if len(e.Ports) > 16 {
					t.Fatalf("Ports has %d entries, want truncated to 16", len(e.Ports))
				}
			}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			rec, err := Open(root, "slice")
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			e := Event{Type: TypeSessionPolicy}
			c.build(&e)
			if err := rec.Append(e); err != nil {
				t.Fatalf("Append refused an event whose only oversized field was %s: %v", c.name, err)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			blob, err := os.ReadFile(Path(root, "slice"))
			if err != nil {
				t.Fatalf("reading the chain back: %v", err)
			}
			for i, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
				if len(line) > MaxLine {
					t.Fatalf("line %d is %d bytes, over MaxLine (%d)", i+1, len(line), MaxLine)
				}
			}
			events, rerr := Read(bytes.NewReader(blob))
			if rerr != nil {
				t.Fatalf("reading back the appended event: %v", rerr)
			}
			if len(events) != 1 {
				t.Fatalf("want 1 event recorded, got %d — the oversized %s field must not make the event vanish", len(events), c.name)
			}
			c.check(t, events[0])
			if _, _, verr := Verify(bytes.NewReader(blob)); verr != nil {
				t.Fatalf("clipped event does not verify: %v", verr)
			}
		})
	}
}

// oversizedSliceValue builds an oversized value for a slice type, generically
// enough to cover every shape a slice field on Event has today and every
// shape docs/policy-record.md §6 says P7-3 is about to add (EvAgent,
// EvStoreKey — both structs with string fields, the same shape EvSecret
// already has). It is used by TestClipLargestFieldCoversEverySliceField below
// rather than a per-field literal, so a new slice field this function does
// not yet know how to grow fails loudly, with a message that says so, instead
// of silently building an undersized value that would let the guard test pass
// for the wrong reason.
func oversizedSliceValue(t *testing.T, sliceType reflect.Type) reflect.Value {
	t.Helper()
	// Comfortably past MaxLine (8<<20) on its own, matching the margin the
	// hand-written cases above already use (10 MiB across 1000 Allow/Plugins/
	// Forwards/Tools elements, 10 MB across 2000 Secrets).
	const targetBytes = 12 << 20
	elem := sliceType.Elem()
	switch elem.Kind() {
	case reflect.String:
		const n = 1200
		each := targetBytes / n
		out := reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			out.Index(i).SetString(strings.Repeat("d", each))
		}
		return out
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		const n = 2 << 20 // ports-shaped: many small integers, not few large ones
		out := reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			out.Index(i).SetInt(int64(10000 + i))
		}
		return out
	case reflect.Struct:
		const n = 600
		each := targetBytes / n
		out := reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			ev := out.Index(i)
			for j := 0; j < ev.NumField(); j++ {
				if fv := ev.Field(j); fv.Kind() == reflect.String && fv.CanSet() {
					fv.SetString(strings.Repeat("d", each))
				}
			}
		}
		return out
	default:
		t.Fatalf("oversizedSliceValue does not know how to grow a []%s (element kind %s) — extend it before this guard test can cover that field",
			elem, elem.Kind())
		return reflect.Value{}
	}
}

// TestClipLargestFieldCoversEverySliceField is docs/policy-record.md §9.1's
// landmine closed structurally rather than by list. F8 closed it for string
// fields with largestStringField's own reflection walk; P7-2 then had to
// reopen the same question for slices by hand, five names at a time
// (recorder.go's clipLargestField), and named five of its own six new slices
// — Tools slipped through (F1, the review that reopened P7-2). A sixth
// hand-written subtest above closes that specific miss, but a hand-maintained
// list has now failed this exact way twice — once for strings, once for
// slices — so this test does not add a seventh name to a list; it walks
// Event by reflection instead, the same way largestStringField itself does,
// and asserts the property directly: give any one slice-kind field on Event
// an oversized value, with every other field left zero, and the event must
// still be recorded — never zero events, because that is the exact shape F8
// and F1 both were.
//
// This covers every slice field Event has today (Argv, Cmd, Allow, Ports,
// Secrets, Plugins, Forwards, Tools) without naming any of them, and — the
// point of writing it this way — will cover P7-3's three new slices (Agents,
// Edges, StoreKeys) the day they are appended to Event, whether or not
// clipLargestField is updated for them: if it is not, this test fails with
// the field's own name in the message, in this exact form, in CI, rather
// than three months later against a real session that lost an event.
func TestClipLargestFieldCoversEverySliceField(t *testing.T) {
	et := reflect.TypeOf(Event{})
	for i := 0; i < et.NumField(); i++ {
		field := et.Field(i)
		if field.Type.Kind() != reflect.Slice {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			root := t.TempDir()
			rec, err := Open(root, "sliceguard")
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			e := Event{Type: TypeSessionPolicy}
			reflect.ValueOf(&e).Elem().Field(i).Set(oversizedSliceValue(t, field.Type))
			if err := rec.Append(e); err != nil {
				t.Fatalf("Append refused an event whose only oversized field was %s: %v", field.Name, err)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			blob, err := os.ReadFile(Path(root, "sliceguard"))
			if err != nil {
				t.Fatalf("reading the chain back: %v", err)
			}
			for j, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
				if len(line) > MaxLine {
					t.Fatalf("line %d is %d bytes, over MaxLine (%d)", j+1, len(line), MaxLine)
				}
			}
			events, rerr := Read(bytes.NewReader(blob))
			if rerr != nil {
				t.Fatalf("reading back the appended event: %v", rerr)
			}
			if len(events) != 1 {
				t.Fatalf("want 1 event recorded, got %d — field %s's oversized value made the event vanish; clipLargestField needs a clip case for it",
					len(events), field.Name)
			}
			if _, _, verr := Verify(bytes.NewReader(blob)); verr != nil {
				t.Fatalf("clipped event does not verify: %v", verr)
			}
		})
	}
}
