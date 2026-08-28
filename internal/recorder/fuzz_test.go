package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
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

// TestAppendClipsEverySessionPolicySlice is F8's fixture repeated for P7-2
// and P7-3's nine new slice fields, named in docs/policy-record.md §9.1 as
// the ones the same reflection gap misses: Allow, Secrets, Plugins, Forwards,
// Tools, Agents and StoreKeys are []string or a struct slice, invisible to
// largestStringField the way Cmd always was; Ports is []int and gets its own
// dedicated clip rather than a string substitution; Edges is []string like
// Allow. Each case is oversized on its own — nothing else on the event
// contributes — so the event vanishing here would be this field's clip
// missing, not some other field masking it.
//
// Tools was the field this test did not cover on P7-2's first pass — the
// review that reopened P7-2 (F1) proved with this exact fixture shape that an
// oversized Tools value made the whole event vanish, since clipLargestField's
// list named the other five and stopped one short. Its subtest below is that
// proof kept as a regression test, and TestClipLargestFieldCoversEverySliceField
// further down backstops the whole list by construction so a further miss
// cannot happen silently — which is what let P7-3's own three (Agents, Edges,
// StoreKeys) be added directly to clipLargestField with the guard test
// confirming coverage, rather than needing the same F1 shape of bug to be
// found and fixed a third time.
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
		{"Agents", func(e *Event) {
			a := make([]EvAgent, 2000)
			for i := range a {
				a[i] = EvAgent{Name: strings.Repeat("n", 5000), Sandbox: strings.Repeat("s", 5000)}
			}
			e.Agents = a
		}, func(t *testing.T, e Event) {
			if len(e.Agents) != 1 || !strings.Contains(e.Agents[0].Name, "clipped from") {
				t.Fatalf("Agents = %v, want one entry noting a clip", e.Agents)
			}
		}},
		{"Edges", func(e *Event) { e.Edges = longStrings(1000, 10<<10) },
			func(t *testing.T, e Event) {
				if len(e.Edges) != 1 || !strings.Contains(e.Edges[0], "clipped from") {
					t.Fatalf("Edges = %v, want one element noting a clip", e.Edges)
				}
			}},
		{"StoreKeys", func(e *Event) {
			s := make([]EvStoreKey, 2000)
			for i := range s {
				s[i] = EvStoreKey{Name: strings.Repeat("n", 5000), Read: []string{strings.Repeat("r", 5000)}}
			}
			e.StoreKeys = s
		}, func(t *testing.T, e Event) {
			if len(e.StoreKeys) != 1 || !strings.Contains(e.StoreKeys[0].Name, "clipped from") {
				t.Fatalf("StoreKeys = %v, want one entry noting a clip", e.StoreKeys)
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
// enough to cover every shape a slice field on Event has today, including
// P7-3's EvAgent and EvStoreKey (both structs with string fields, the same
// shape EvSecret already has). It is used by
// TestClipLargestFieldCoversEverySliceField below rather than a per-field
// literal, so a new slice field this function does not yet know how to grow
// fails loudly, with a message that says so, instead of silently building an
// undersized value that would let the guard test pass for the wrong reason.
//
// The reflect.Struct case only sets a struct's string-kinded fields — so an
// element type with no string field at all (EvStoreKey's Read/Write are
// []string, not string, and are skipped the same way) would build a value
// that never actually grows, and the guard test built on top of it would then
// pass vacuously rather than because clipping genuinely worked. Neither
// EvAgent nor EvStoreKey hits this today (both have a string Name), so this
// has not fired for real, but the marshal-and-measure check at the end below
// is what makes a *future* such case fail loudly instead of passing silent —
// a non-blocking note from the review that confirmed P7-2's fixes GO,
// applied here before P7-3 needed it for real.
func oversizedSliceValue(t *testing.T, sliceType reflect.Type) reflect.Value {
	t.Helper()
	// Comfortably past MaxLine (8<<20) on its own, matching the margin the
	// hand-written cases above already use (10 MiB across 1000 Allow/Plugins/
	// Forwards/Tools elements, 10 MB across 2000 Secrets).
	const targetBytes = 12 << 20
	elem := sliceType.Elem()
	var out reflect.Value
	switch elem.Kind() {
	case reflect.String:
		const n = 1200
		each := targetBytes / n
		out = reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			out.Index(i).SetString(strings.Repeat("d", each))
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		const n = 2 << 20 // ports-shaped: many small integers, not few large ones
		out = reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			out.Index(i).SetInt(int64(10000 + i))
		}
	case reflect.Struct:
		const n = 600
		each := targetBytes / n
		out = reflect.MakeSlice(sliceType, n, n)
		for i := 0; i < n; i++ {
			ev := out.Index(i)
			for j := 0; j < ev.NumField(); j++ {
				if fv := ev.Field(j); fv.Kind() == reflect.String && fv.CanSet() {
					fv.SetString(strings.Repeat("d", each))
				}
			}
		}
	default:
		t.Fatalf("oversizedSliceValue does not know how to grow a []%s (element kind %s) — extend it before this guard test can cover that field",
			elem, elem.Kind())
		return reflect.Value{}
	}

	b, err := json.Marshal(out.Interface())
	if err != nil {
		t.Fatalf("oversizedSliceValue's own output for %s does not even marshal: %v", sliceType, err)
	}
	if len(b) <= MaxLine {
		t.Fatalf("oversizedSliceValue built a %s slice that marshals to only %d bytes — not actually "+
			"oversized (MaxLine is %d). Its element type has no field this function knows how to grow "+
			"(reflect.Struct only fills string-kinded fields) — extend it for this element shape.",
			sliceType, len(b), MaxLine)
	}
	return out
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

// FuzzEraseRoundTrip drives Erase's own parser (P7-17, F6).
//
// F6 replaced Erase's rewrite: it used to go Read -> redact -> hash ->
// re-marshal, and Read is json.Unmarshal into Event, so every member this
// build's struct did not carry was dropped. The replacement holds each line as
// its own members and writes back only the ones a redaction changed — which
// means parseObject and applyRedaction are now a second parser on the audit
// chain, beside Verify and Read. A parser on the evidence path without a fuzz
// target is the gap P6-3 was written about, and this is that gap closed for
// the parser F6 added.
//
// The property, on any line at all: erase either refuses and leaves the chain
// byte-for-byte as it was, or rewrites it into something that still verifies,
// still reads back as events, keeps every member it was not entitled to
// redact byte-for-byte, keeps the order of every member, and loses no member
// name at any depth — including names inside objects this build's own structs
// do not fully know, which is the whole of what F6 was about.
//
// The fuzzed line becomes the first event of a real three-event chain: it,
// then a command.output that is always redactable so Erase never refuses for
// want of anything to do, then a session.end so it never refuses for want of
// one. seq, prev and hash are stripped from the fuzzed line and re-added, so
// the input is a chain rather than three unrelated objects — but a duplicate
// of any OTHER name is left exactly where the fuzzer put it, because refusing
// one is behaviour worth reaching.
func FuzzEraseRoundTrip(f *testing.F) {
	// An ordinary event with two redactable fields.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.start","source":"host","call":"c1","cmd":["curl","https://api.example.com/"],"cwd":"/work/jane"}`)
	// A member this build's Event does not carry — F6's own case.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.start","source":"host","cwd":"/work/jane","quarantined_by":"policy-v2"}`)
	// A member this build does not carry, one level down, inside a struct
	// slice it does: TestF6_EraseKeepsANestedFieldThisBuildDoesNotKnow.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"team.topology","source":"host","agents":[{"name":"planner","sandbox":"aa11bb22","region":"eu-central-1"}],"edges":["planner -> worker"]}`)
	// And one inside *EvError, which is the pointer-to-struct descent.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.exit","source":"host","error":{"kind":"internal","message":"exec: \"/tmp/x\": not found","detail":"from a newer build"}}`)
	// An explicit zero omitempty would have dropped on a struct round trip.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.output","source":"host","data":"Zm9v","bytes":0}`)
	// A duplicate member name: json.Unmarshal keeps the last, parseObject
	// keeps the first, so the rewrite refuses rather than picking one.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.output","source":"host","data":"Zm9v","data":"YmFy"}`)
	// Valid JSON, not an object.
	f.Add(`[1,2,3]`)
	// Valid JSON, an object, nothing else.
	f.Add(`{}`)
	// The mixed struct slice: StoreKeys.Name is content, Read and Write are not.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"team.topology","source":"host","store_keys":[{"name":"plan","read":["a"],"write":["b"]}]}`)
	// Already a fingerprint from an earlier erasure (B2's path).
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.output","source":"host","data":"(erased — sha256:` + strings.Repeat("ab", 32) + `)"}`)
	// An empty redactable field: nothing to redact, and not counted.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.output","source":"host","data":"","cwd":""}`)
	// A nested `hash` member ahead of the real one, which is what would break
	// the digest substitution if it were not anchored on the value.
	f.Add(`{"v":1,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.exit","source":"host","error":{"kind":"x","message":"y"},"extra":{"hash":""}}`)
	// A schema version ahead of this build: refused before any rewrite.
	f.Add(`{"v":99,"ts":"2026-01-01T00:00:00.000Z","sandbox":"fz","type":"command.output","source":"host","data":"Zm9v"}`)
	// Not JSON at all.
	f.Add(`not json`)

	f.Fuzz(func(t *testing.T, line string) {
		// One event per line is the file format; a line that carries a newline
		// is not one line.
		if strings.ContainsAny(line, "\n\r") {
			return
		}
		root := t.TempDir()
		const id = "fz"
		path := Path(root, id)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}

		first, ok := chainableLine([]byte(line), 1, "")
		if !ok {
			// Not an object, so it can never be an event. Erase must refuse it
			// and leave it alone — the file is the evidence, and a refusal
			// that has already half-rewritten it is not a refusal.
			writeChainFile(t, path, [][]byte{[]byte(line)})
			assertRefusedAndUntouched(t, root, id, path)
			return
		}

		// A command.output that is always redactable, so Erase never refuses
		// for want of something to do, and a session.end so it never refuses
		// for want of one.
		second, ok := chainableLine([]byte(`{"v":1,"ts":"2026-01-01T00:00:01.000Z","sandbox":"fz","type":"command.output","source":"host","call":"c1","stream":"stdout","data":"Zm9vCg==","bytes":4}`), 2, digestOf(first))
		if !ok {
			t.Fatal("this target's own fixed second line is not chainable")
		}
		third, ok := chainableLine([]byte(`{"v":1,"ts":"2026-01-01T00:00:02.000Z","sandbox":"fz","type":"session.end","source":"host","reason":"shutdown"}`), 3, digestOf(second))
		if !ok {
			t.Fatal("this target's own fixed third line is not chainable")
		}
		writeChainFile(t, path, [][]byte{first, second, third})

		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Erase(root, id, "fuzz"); err != nil {
			assertUntouched(t, path, before, err)
			return
		}

		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		events, head, verr := Verify(bytes.NewReader(after))
		if verr != nil {
			t.Fatalf("Erase rewrote the chain into one that does not verify: %v\nbefore:\n%s\nafter:\n%s", verr, before, after)
		}
		if events != 4 {
			t.Fatalf("Verify counted %d events after erasing a 3-event chain, want 4 (the erasure event is appended)", events)
		}
		if head == "" {
			t.Fatal("the rewritten chain has no head")
		}
		parsed, rerr := Read(bytes.NewReader(after))
		if rerr != nil {
			t.Fatalf("Verify accepted the rewritten chain but Read refused it: %v\nafter:\n%s", rerr, after)
		}
		if len(parsed) != events {
			t.Fatalf("Verify counted %d events and Read found %d in the rewritten chain", events, len(parsed))
		}

		last := parsed[len(parsed)-1]
		if last.Type != TypeSessionErasure {
			t.Fatalf("the rewritten chain's last event is %q, want %q", last.Type, TypeSessionErasure)
		}
		if last.Modified < 1 {
			t.Fatalf("Erase succeeded but the erasure event says %d events were modified", last.Modified)
		}
		if last.RedactedFields < last.Modified {
			t.Fatalf("erasure event: redacted_fields=%d is below modified=%d — every event counted "+
				"as touched had at least one field replaced", last.RedactedFields, last.Modified)
		}

		// The fuzzed line, before and after, is what F6 is actually about.
		gotLine := bytes.Split(bytes.TrimRight(after, "\n"), []byte("\n"))[0]
		assertRewriteKeptEverythingItShould(t, first, gotLine)
	})
}

// --- FuzzEraseRoundTrip's own helpers ----------------------------------------
//
// None of these use parseObject or applyRedaction. A fuzz target whose fixture
// builder and whose oracle are the code under test can only ever agree with
// it, which is the one thing a target on a parser must not do.

// jsonMember is one member of a JSON object as the bytes carried it. A slice
// of these rather than a map, because a map would silently collapse a
// duplicate name and a duplicate name is one of the inputs worth reaching.
type jsonMember struct {
	key   string
	value json.RawMessage
}

// splitMembers reads a JSON object's members in order, keeping duplicates.
func splitMembers(raw []byte) ([]jsonMember, bool) {
	var probe map[string]json.RawMessage
	if json.Unmarshal(raw, &probe) != nil {
		return nil, false // not valid JSON, or valid JSON that is not an object
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, false
	}
	var out []jsonMember
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := kt.(string)
		if !ok {
			return nil, false
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, false
		}
		out = append(out, jsonMember{key, v})
	}
	return out, true
}

func renderMembers(ms []jsonMember) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m.key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(m.value)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// chainableLine turns one candidate object into a line that can sit at
// position seq of a chain: its own seq, prev and hash are dropped wherever
// they were and re-added at the end, and the digest is computed over the bytes
// as written — which is what digestOfLine reconstructs on a read. Every other
// member, including a duplicate one, is left exactly where and as it was.
func chainableLine(raw []byte, seq int, prev string) ([]byte, bool) {
	ms, ok := splitMembers(raw)
	if !ok {
		return nil, false
	}
	kept := ms[:0:0]
	for _, m := range ms {
		switch m.key {
		case "seq", "prev", "hash":
		default:
			kept = append(kept, m)
		}
	}
	kept = append(kept,
		jsonMember{"seq", json.RawMessage(strconv.Itoa(seq))},
		jsonMember{"prev", mustJSON(prev)},
		jsonMember{"hash", json.RawMessage(`""`)},
	)
	line := renderMembers(kept)
	if bytes.ContainsAny(line, "\n\r") {
		return nil, false
	}
	sum := sha256.Sum256(line)
	digest := hex.EncodeToString(sum[:])
	// Anchored on the exact bytes this function just wrote, which are the LAST
	// `"hash":""` in the line — a nested one the fuzzer supplied earlier would
	// otherwise take the substitution.
	i := bytes.LastIndex(line, []byte(`"hash":""`))
	if i < 0 {
		return nil, false
	}
	out := append([]byte{}, line[:i]...)
	out = append(out, []byte(`"hash":"`+digest+`"`)...)
	out = append(out, line[i+len(`"hash":""`):]...)
	return out, true
}

// digestOf reads back the hash a chainableLine line carries.
func digestOf(line []byte) string {
	var e Event
	if json.Unmarshal(line, &e) != nil {
		return ""
	}
	return e.Hash
}

func mustJSON(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

func writeChainFile(t *testing.T, path string, lines [][]byte) {
	t.Helper()
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertRefusedAndUntouched(t *testing.T, root, id, path string) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	_, eraseErr := Erase(root, id, "fuzz")
	if eraseErr == nil {
		t.Fatalf("Erase accepted a chain whose first line is not an event:\n%s", before)
	}
	assertUntouched(t, path, before, eraseErr)
}

// assertUntouched is the property a refusal has to carry. Erase rewrites the
// file in place, on the same inode, so "it refused" and "it did not write" are
// two different claims and only the second one protects the evidence.
func assertUntouched(t *testing.T, path string, before []byte, eraseErr error) {
	t.Helper()
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("Erase refused (%v) and rewrote the chain anyway\nbefore:\n%s\nafter:\n%s", eraseErr, before, after)
	}
}

// assertRewriteKeptEverythingItShould is the oracle: what a lossless rewrite
// is allowed to have changed, and nothing else.
func assertRewriteKeptEverythingItShould(t *testing.T, before, after []byte) {
	t.Helper()
	wantMembers, ok := splitMembers(before)
	if !ok {
		t.Fatalf("this target built an unparseable line: %s", before)
	}
	gotMembers, ok := splitMembers(after)
	if !ok {
		t.Fatalf("Erase wrote a line that is not a JSON object: %s", after)
	}

	if len(gotMembers) != len(wantMembers) {
		t.Fatalf("the rewritten line has %d members and the original had %d\nbefore:\n%s\nafter:\n%s",
			len(gotMembers), len(wantMembers), before, after)
	}
	redactable := redactableMembers()
	for i := range wantMembers {
		w, g := wantMembers[i], gotMembers[i]
		if w.key != g.key {
			t.Fatalf("member %d is %q in the rewritten line and %q in the original — the order of a "+
				"line's members is what every digest over it is computed on\nbefore:\n%s\nafter:\n%s",
				i, g.key, w.key, before, after)
		}
		switch w.key {
		case "seq", "prev", "hash":
			continue // rewritten by design: the whole chain is rehashed
		}
		if redactable[w.key] {
			continue // erase is entitled to replace this one's value
		}
		if !bytes.Equal(w.value, g.value) {
			t.Fatalf("member %q is not redactable but its value changed from %s to %s — a rewrite may "+
				"only touch what a redaction is entitled to touch", w.key, w.value, g.value)
		}
	}

	// And no member NAME may go missing at any depth, including inside a
	// member erase was entitled to rewrite. This is the F6 property stated
	// where it is hardest to hold: a newer build's field inside *EvError or
	// inside an element of a struct slice.
	if wantShape, gotShape := memberShape(before), memberShape(after); wantShape != gotShape {
		t.Fatalf("the rewritten line lost or gained a member somewhere\n  before: %s\n  after:  %s\nbefore:\n%s\nafter:\n%s",
			wantShape, gotShape, before, after)
	}
}

// memberShape renders a value's member NAMES at every depth and nothing else:
// an object becomes its sorted `name:shape` pairs, an array becomes the set of
// its elements' shapes, and any scalar becomes ".".
//
// Values are deliberately invisible to it, because a redaction changes values
// by design. An array is a SET of its elements' shapes rather than a list, so
// that a []string collapsing from four elements to one fingerprint reads the
// same both ways while a struct element losing one of its own members does
// not.
func memberShape(raw json.RawMessage) string {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil && obj != nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+":"+memberShape(obj[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil && arr != nil {
		seen := map[string]bool{}
		for _, e := range arr {
			seen[memberShape(e)] = true
		}
		shapes := make([]string, 0, len(seen))
		for s := range seen {
			shapes = append(shapes, s)
		}
		sort.Strings(shapes)
		return "[" + strings.Join(shapes, "|") + "]"
	}
	return "."
}

// redactableMembers is every top-level member name Erase is entitled to
// replace: derived from Event and eraseExempt rather than listed, so a field
// that becomes redactable later is not silently excused from the byte-for-byte
// check above. The json tag is read here rather than through erase.go's own
// jsonName, for the reason the helpers above give: the oracle does not borrow
// from the code it is judging.
func redactableMembers() map[string]bool {
	out := map[string]bool{}
	tag := func(f reflect.StructField) string {
		name := f.Tag.Get("json")
		if i := strings.IndexByte(name, ','); i >= 0 {
			name = name[:i]
		}
		if name == "" {
			return f.Name
		}
		return name
	}
	anyInnerRedactable := func(outer string, st reflect.Type) bool {
		for j := 0; j < st.NumField(); j++ {
			if _, exempt := eraseExempt[outer+"."+st.Field(j).Name]; !exempt {
				return true
			}
		}
		return false
	}
	et := reflect.TypeOf(Event{})
	for i := 0; i < et.NumField(); i++ {
		f := et.Field(i)
		_, exempt := eraseExempt[f.Name]
		switch f.Type.Kind() {
		case reflect.String:
			if !exempt {
				out[tag(f)] = true
			}
		case reflect.Slice:
			switch f.Type.Elem().Kind() {
			case reflect.String:
				if !exempt {
					out[tag(f)] = true
				}
			case reflect.Struct:
				if anyInnerRedactable(f.Name, f.Type.Elem()) {
					out[tag(f)] = true
				}
			}
		case reflect.Ptr:
			if f.Type.Elem().Kind() == reflect.Struct && anyInnerRedactable(f.Name, f.Type.Elem()) {
				out[tag(f)] = true
			}
		}
	}
	return out
}
