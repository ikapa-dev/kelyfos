package recorder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/proto"
)

// P7-15, pinned as assertions rather than as a symptom (D80).
//
// D69 opened P7-15 as a test-harness problem: FuzzAppendFieldValues OOM-kills
// its own worker once its corpus grows. It is not one. The kill and a
// recording-integrity defect in a shipped release are the same defect, out of
// one line of reasoning in fitUnderMaxLine, and the four tests here are that
// line of reasoning stated from four sides.
//
//   - The clip loop reduced ONE field per attempt, by half, bounded at
//     maxClipAttempts attempts. Eight halvings of one field cannot bring an
//     event under MaxLine when the bulk is spread across more than about eight
//     fields, so Append failed closed and the event vanished from the record —
//     F8's failure mode reached by breadth instead of by an uncovered field.
//     TestAppendKeepsAnEventWhoseBulkIsSpreadAcrossManyFields is the mechanism.
//
//   - TestAppendKeepsTheCommandStartTheMCPBridgeCanBuild is whether any real
//     caller can reach it, which is what decides the severity. One can:
//     `kelyfos mcp`, on an ordinary `tools/call` for `exec`.
//
//   - Because the loop could not converge it spent all nine of its
//     json.Marshal calls at nearly full size. One Append of an event holding
//     340 MiB across its fields allocated between 4.3 and 7.6 GiB — the spread
//     is encoding/json's own buffer pool, not noise in the measurement — and
//     left a 4.4 GiB resident set. TestAppendAllocatesAgainstMaxLineNotAgainstTheEventHandedToIt
//     is that half, and it measures 80.2 MiB now, stable to a kilobyte across
//     runs.
//
//   - TestClippingKeepsWhatItCanRatherThanHalvingUntilItFits is the property
//     that keeps a later simplification from putting halving back.
//
// One fix answers all of it: converge, rather than take more attempts. Raising
// maxClipAttempts is the change that looks like a fix and is the opposite of
// one — more attempts at nearly full size is more allocation, not less, and
// the numbers are in the comment on maxClipAttempts itself.

// settableStringFields names every string field a caller can still see on a
// written event: every string field reachable from Event, less the four
// appendLocked stamps over on its way through (TS, Sandbox, Prev, Hash).
// Computed rather than written down so that a field added to Event does not
// silently change what these tests think they are exercising.
func settableStringFields(t testing.TB) []string {
	t.Helper()
	stamped := map[string]bool{"TS": true, "Sandbox": true, "Prev": true, "Hash": true}
	var out []string
	et := reflect.TypeOf(Event{})
	for i := 0; i < et.NumField(); i++ {
		f := et.Field(i)
		if stamped[f.Name] {
			continue
		}
		switch f.Type.Kind() {
		case reflect.String:
			out = append(out, f.Name)
		case reflect.Ptr:
			if f.Type.Elem().Kind() != reflect.Struct {
				continue
			}
			st := f.Type.Elem()
			for j := 0; j < st.NumField(); j++ {
				if st.Field(j).Type.Kind() == reflect.String {
					out = append(out, f.Name+"."+st.Field(j).Name)
				}
			}
		}
	}
	return out
}

// setStringFields puts s into the first n fields settableStringFields named,
// allocating a pointed-to struct if one is needed to reach a field. It reports
// how many it actually set, which is n unless Event has fewer fields than the
// case asked for — a case that asked for more than exist is still a valid
// case, it is just a narrower one than its name says, and the caller says so.
func setStringFields(t testing.TB, e *Event, n int, s string) int {
	t.Helper()
	names := settableStringFields(t)
	if n > len(names) {
		n = len(names)
	}
	v := reflect.ValueOf(e).Elem()
	for _, name := range names[:n] {
		outer, inner, nested := strings.Cut(name, ".")
		fv := v.FieldByName(outer)
		if !nested {
			fv.SetString(s)
			continue
		}
		if fv.IsNil() {
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		fv.Elem().FieldByName(inner).SetString(s)
	}
	return n
}

// TestAppendKeepsAnEventWhoseBulkIsSpreadAcrossManyFields is P7-15's
// recording-integrity half, and it is the same assertion
// TestAppendClipsOversizedEvErrorMessage makes for F8: an event Append cannot
// write whole must be written CLIPPED, never dropped. F8 reached that failure
// by putting the bulk in a field the clip could not see; this reaches it by
// putting the bulk in fields the clip can see perfectly well and simply cannot
// get through, because it reduced one of them per attempt and had eight
// attempts.
//
// The cases are the sweep run directly through fitUnderMaxLine on the parent
// (v1.1). One 20 MiB field is clipped and kept; 16 MiB spread over eight is
// dropped, over the limit by 512 bytes; wider is dropped by more. The 40-field
// case is the shape FuzzAppendFieldValues' own setAllStringFields builds, and
// on the parent it does not merely drop the event, it breaks the chain the
// test writes around it.
func TestAppendKeepsAnEventWhoseBulkIsSpreadAcrossManyFields(t *testing.T) {
	cases := []struct {
		name   string
		fields int
		each   int
	}{
		{"one 20 MiB field", 1, 20 << 20},
		{"four 4 MiB fields", 4, 4 << 20},
		{"eight 1 MiB fields", 8, 1 << 20},
		{"eight 2 MiB fields", 8, 2 << 20},
		{"sixteen 1 MiB fields", 16, 1 << 20},
		{"twenty-four 1 MiB fields", 24, 1 << 20},
		{"every string field at 1 MiB", 64, 1 << 20},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			rec, err := Open(root, "spread")
			if err != nil {
				t.Fatalf("open: %v", err)
			}

			e := Event{Type: TypeCommandOutput}
			set := setStringFields(t, &e, c.fields, strings.Repeat("s", c.each))
			e.Type = TypeCommandOutput // setStringFields may have overwritten it

			// Bracketed the way FuzzAppendFieldValues brackets its own
			// oversized event: a refused event in the middle has to show up as
			// a broken chain rather than merely a short one, because a
			// recorder that drops an event and carries on is the outcome this
			// whole guard exists to prevent.
			if err := rec.Append(Event{Type: TypeSessionStart}); err != nil {
				t.Fatalf("appending the opening event: %v", err)
			}
			appendErr := rec.Append(e)
			endErr := rec.Append(Event{Type: TypeSessionEnd})
			if err := rec.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}

			if appendErr != nil {
				t.Fatalf("Append refused an event carrying %d bytes across %d string fields: %v\n"+
					"An event too large to write whole must be written clipped, not dropped.",
					set*c.each, set, appendErr)
			}
			if endErr != nil {
				t.Fatalf("the event after the oversized one was refused too: %v", endErr)
			}

			blob, err := os.ReadFile(Path(root, "spread"))
			if err != nil {
				t.Fatalf("reading the chain back: %v", err)
			}
			for i, line := range bytes.Split(bytes.TrimRight(blob, "\n"), []byte("\n")) {
				if len(line) > MaxLine {
					t.Fatalf("line %d is %d bytes, over MaxLine (%d)", i+1, len(line), MaxLine)
				}
			}
			n, _, verr := Verify(bytes.NewReader(blob))
			if verr != nil {
				t.Fatalf("the chain around the clipped event does not verify: %v", verr)
			}
			if n != 3 {
				t.Fatalf("Verify counted %d events, want 3 — the oversized event must be kept in "+
					"truncated form between the two ordinary ones", n)
			}

			events, rerr := Read(bytes.NewReader(blob))
			if rerr != nil {
				t.Fatalf("Verify accepted the chain but Read refused the same bytes: %v", rerr)
			}
			if events[1].Type != TypeCommandOutput {
				t.Fatalf("the middle event is %q, want %q", events[1].Type, TypeCommandOutput)
			}
		})
	}
}

// TestAppendKeepsTheCommandStartTheMCPBridgeCanBuild is the reachability
// question answered as a fixture rather than as a paragraph. It is the reason
// P7-15 is a `### Fixed` line in a release and not a note about a test harness.
//
// `kelyfos mcp` tees the client's stdin and records what it sees
// (host/mcpobserve.go). On a `tools/call` for `exec` it appends a
// command.start built entirely out of that one frame, and THREE of its fields
// have no length bound anywhere between the wire and Append:
//
//	Call: "m" + strings.Trim(string(req.ID), `"`)   // mcpobserve.go:212
//	Cmd:  execArgv(args)                            // args["argv"], or /bin/sh -c args["command"]
//	Cwd:  str(args["cwd"])                          // mcpobserve.go:225
//
// `req.ID` is a json.RawMessage — the JSON-RPC id is copied out of the frame
// with no type check and no length check — and the only ceiling on any of the
// three is the tee scanner's own buffer, proto.MaxMCPLine. The event is
// appended the moment the call is seen, before the guest has any say in it.
//
// The filler is '<'. encoding/json escapes '<', '>' and '&' to < and so
// on by default, six bytes out per byte in, so a frame's worth of '<' spread
// across three fields is what turns a door that would otherwise converge into
// one that does not. That is not a curiosity: '<' is what an agent driving a
// shell through this bridge sends every time it redirects a file.
//
// The sizing is derived from proto.MaxMCPLine rather than written down, so
// that this fixture tracks the real frame limit instead of a copy of it that
// can drift away from it silently — which is the mistake docs/policy-record.md
// §9.1's own stale line numbers are a monument to.
func TestAppendKeepsTheCommandStartTheMCPBridgeCanBuild(t *testing.T) {
	// A third of the frame each, less the JSON around them.
	each := proto.MaxMCPLine/3 - 4096
	filler := strings.Repeat("<", each)

	root := t.TempDir()
	rec, err := Open(root, "mcpdoor")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	err = rec.Append(Event{
		Type: TypeCommandStart,
		Call: "m" + filler,
		Cmd:  []string{"/bin/sh", "-c", filler},
		Cwd:  filler,
		Via:  "mcp",
	})
	if err != nil {
		t.Fatalf("Append refused the command.start a %d byte MCP frame can build: %v\n"+
			"host/mcpobserve.go builds Call, Cmd and Cwd from one tools/call frame with no length "+
			"bound on any of them. An event that door can produce must be recorded clipped, not dropped: "+
			"a dropped event also latches the recorder (F13), which takes the machine down with it.",
			proto.MaxMCPLine, err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	blob, err := os.ReadFile(Path(root, "mcpdoor"))
	if err != nil {
		t.Fatalf("reading the chain back: %v", err)
	}
	if len(bytes.TrimRight(blob, "\n")) > MaxLine {
		t.Fatalf("the written line is %d bytes, over MaxLine (%d)", len(bytes.TrimRight(blob, "\n")), MaxLine)
	}
	events, rerr := Read(bytes.NewReader(blob))
	if rerr != nil {
		t.Fatalf("reading the appended event back: %v", rerr)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event recorded, got %d", len(events))
	}
	// Every one of the three has to survive with CONTENT in it, not merely be
	// non-empty. An earlier version of this test asserted only that the fields
	// were non-empty, and a build that reduced all three to a bare
	// "...(clipped from N to 0 bytes)" note — 36 bytes, no argv, no path, no
	// call id — passed it while writing a record that answers nothing. The
	// floor is deliberately far below what a correct clip retains (the three
	// share a budget of MaxLine, so each gets roughly MaxLine/3 before
	// escaping): it is here to catch a collapse, not to pin a ratio.
	got := events[0]
	const floor = MaxLine / 64
	if len(got.Call) < floor || len(got.Cwd) < floor || len(got.Cmd) == 0 || len(got.Cmd[0]) < floor {
		t.Fatalf("the clipped event kept almost nothing: call=%d bytes, cmd=%d elements (first %d bytes), "+
			"cwd=%d bytes, each of which should hold at least %d.\n"+
			"An event too large to write whole must be written CLIPPED — a record reduced to three notes "+
			"saying something was dropped is the same lost evidence as dropping the event.",
			len(got.Call), len(got.Cmd), len(got.Cmd[0]), len(got.Cwd), floor)
	}
	if _, _, verr := Verify(bytes.NewReader(blob)); verr != nil {
		t.Fatalf("the clipped event does not verify: %v", verr)
	}
}

// TestAppendAllocatesAgainstMaxLineNotAgainstTheEventHandedToIt is P7-15's
// memory half, stated as the assertion the OOM never was: "it gets killed" is
// a fact about one machine's RAM and one corpus, and it cannot fail on a
// machine with more of the first or a run with less of the second. What is
// actually wrong is that Append's cost scaled with what the CALLER handed it
// rather than with the line Append is allowed to write, and a TotalAlloc delta
// says that in a number.
//
// The input is FuzzAppendFieldValues' own worst seed, replayed exactly:
// setAllStringFields with a 9 MiB value. That reaches 36 string fields — every
// string on Event and *EvError less the four appendLocked stamps over — all
// sharing one backing array, so it is 9 MiB of distinct bytes and roughly
// 340 MiB of field content. On this machine the parent allocated between
// 4278.6 and 7621.7 MiB for it across five runs, bimodally, because
// encoding/json reuses a pooled buffer when one of the right size happens to
// be free; the fix allocates 80.2 MiB every time.
//
// The ceiling is not either of those numbers, it is the shape: whatever the
// caller hands Append, the work Append does is bounded by MaxLine. 24 x MaxLine
// leaves room for the four marshals one Append genuinely needs (the pre-pass's,
// the fit loop's correction, hashOf's and the line's) plus the slack an
// append-grown buffer costs, and it is loose enough not to go red on a
// different allocator. It is not tight enough to notice a 2x regression: the
// tests above are what pin the behaviour, and this one exists to catch a return
// to allocating against the caller's event, which is fifty times over.
func TestAppendAllocatesAgainstMaxLineNotAgainstTheEventHandedToIt(t *testing.T) {
	const ceiling = 24 * MaxLine // 192 MiB

	root := t.TempDir()
	rec, err := Open(root, "alloc")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rec.Close()

	// Built before the measurement so the 9 MiB string and the event itself
	// are not counted against Append.
	value := strings.Repeat("m", 9<<20)
	e := Event{Bytes: len(value)}
	setAllStringFields(&e, value)
	e.Type = TypeCommandOutput

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	appendErr := rec.Append(e)
	runtime.ReadMemStats(&after)
	used := after.TotalAlloc - before.TotalAlloc

	t.Logf("one Append of %d string fields at %d bytes each allocated %d bytes (%.1f MiB)",
		len(settableStringFields(t)), len(value), used, float64(used)/(1<<20))
	// The allocation is checked BEFORE the error, deliberately: on a build
	// where the clip loop cannot converge, Append both allocates enormously
	// and then refuses, and the number is the finding. Checking the error
	// first would report the refusal and never print the number this test is
	// named for.
	if used > ceiling {
		t.Fatalf("one Append allocated %d bytes (%.1f MiB), over the %d byte (%d MiB) ceiling.\n"+
			"Append's cost must be bounded by MaxLine (%d), not by the total the caller put on the event: "+
			"a clip loop that cannot converge re-marshals the whole thing on every attempt.",
			used, float64(used)/(1<<20), ceiling, ceiling>>20, MaxLine)
	}
	if appendErr != nil {
		t.Fatalf("Append refused the all-string-fields event: %v", appendErr)
	}

	// The event still has to be there, clipped — an Append that allocated
	// little because it refused the event early would pass the ceiling above
	// and fail the whole point of it.
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	blob, err := os.ReadFile(Path(root, "alloc"))
	if err != nil {
		t.Fatalf("reading the chain back: %v", err)
	}
	events, rerr := Read(bytes.NewReader(blob))
	if rerr != nil {
		t.Fatalf("reading the appended event back: %v", rerr)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event recorded, got %d", len(events))
	}
	if _, _, verr := Verify(bytes.NewReader(blob)); verr != nil {
		t.Fatalf("the clipped event does not verify: %v", verr)
	}
}

// TestClippingKeepsWhatItCanRatherThanHalvingUntilItFits is the second-order
// property the convergence fix buys, pinned so a later "simplification" back to
// halving is caught by something other than the two tests above.
//
// Halving reduced to whatever power of two happened to land under the limit: a
// 20 MiB field became 5 MiB, throwing away 3 MiB of record the line had room
// for. Scaling to the ratio actually needed keeps the field at the size the
// budget allows.
//
// The filler matters more than it looks, and the first version of this test got
// it wrong. With a filler that does not escape, the pre-pass alone brings the
// event under the budget and the correction loop never runs — so the test
// passed while the loop's own arithmetic was inverted and reduced an escaping
// event to a 232-byte line. encoding/json escapes `"` to two bytes and `<` to
// six, so the two cases below are the ones that actually exercise the step, and
// `<` is not an exotic input: it is what a shell transcript is full of.
func TestClippingKeepsWhatItCanRatherThanHalvingUntilItFits(t *testing.T) {
	cases := []struct {
		name string
		data string
		// least is the fraction of MaxLine the written line must reach. A
		// value that escapes n:1 cannot fill the line with more than 1/n of
		// its own bytes, so the bar is lower for `<` — but "lower" is still
		// megabytes, and the collapse this guards against is three orders of
		// magnitude below it.
		least float64
	}{
		{"plain", strings.Repeat("d", 20<<20), 0.75},
		{"quoted every 200 bytes", strings.Repeat(strings.Repeat("a", 199)+`"`, (20<<20)/200), 0.75},
		{"angle brackets, six bytes each once escaped", strings.Repeat("<", 20<<20), 0.50},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			rec, err := Open(root, "proportion")
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := rec.Append(Event{Type: TypeCommandOutput, Data: c.data}); err != nil {
				t.Fatalf("Append refused a single oversized Data field: %v", err)
			}
			if err := rec.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			blob, err := os.ReadFile(Path(root, "proportion"))
			if err != nil {
				t.Fatalf("reading the chain back: %v", err)
			}
			line := bytes.TrimRight(blob, "\n")
			if len(line) > MaxLine {
				t.Fatalf("the written line is %d bytes, over MaxLine (%d)", len(line), MaxLine)
			}
			var e Event
			if err := json.Unmarshal(line, &e); err != nil {
				t.Fatalf("the written line does not parse: %v", err)
			}
			t.Logf("%s: line %d bytes (%.1f%% of MaxLine), Data kept %d of %d",
				c.name, len(line), 100*float64(len(line))/float64(MaxLine), len(e.Data), len(c.data))
			if want := int(float64(MaxLine) * c.least); len(line) < want {
				t.Fatalf("the written line is %d bytes and MaxLine is %d — clipping threw away more of "+
					"the record than it had to (wanted at least %d).\n"+
					"It must reduce a field to the size the budget allows, not halve it until a power of "+
					"two happens to fit, and it must not treat an excess larger than the budget as a "+
					"reason to reduce every field to its own clip note.", len(line), MaxLine, want)
			}
			if !strings.Contains(e.Data, "clipped from") {
				t.Fatalf("Data does not carry the clip note")
			}
			// The note has to name the ORIGINAL size, not the size the field
			// had partway through the reduction. A field the loop touches more
			// than once used to report the intermediate value.
			if !strings.Contains(e.Data, fmt.Sprintf("clipped from %d to", len(c.data))) {
				tail := e.Data
				if len(tail) > 120 {
					tail = tail[len(tail)-120:]
				}
				t.Fatalf("the clip note does not name the original %d bytes; it ends %q.\n"+
					"A note derived from an already-clipped value understates what the record lost.",
					len(c.data), tail)
			}
		})
	}
}
