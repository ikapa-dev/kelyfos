package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ikapa-dev/kelyfos/internal/mcp"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
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
	// Since the audit of 2026-09-01 (A1), callTool hands every call to
	// runCall, which holds the panic net and the audit pair together — a
	// recovery has to record the call it refused, so the pair moved with the
	// dispatch. The structural claim is the same and now has two links:
	// callTool goes through runCall, and runCall both audits and dispatches
	// through the one place.
	src := readSource(t, "servemcp.go")
	i := strings.Index(src, "func (s *hostServer) callTool(")
	if i < 0 {
		t.Fatal("callTool is gone; this test needs rewriting with it")
	}
	body := src[i:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "s.runCall(p)") {
		t.Error("callTool does not route through runCall; a call that bypasses it bypasses the record and the panic net")
	}

	i = strings.Index(src, "func (s *hostServer) runCall(")
	if i < 0 {
		t.Fatal("runCall is gone; this test needs rewriting with it")
	}
	body = src[i:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, "s.auditCall(p)") {
		t.Error("runCall does not audit; a tool call that is not recorded is a door with no record")
	}
	if !strings.Contains(body, "s.dispatchTool(p)") {
		t.Error("runCall no longer dispatches through one place")
	}
	if !strings.Contains(body, "recover()") {
		t.Error("runCall lost the panic net; a tool that panics would kill this server and orphan its machines")
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

// A content key is redacted for its name, not for the type the caller chose to
// put under it. The caller picks both, so a guard that only recognises a string
// leaves the same bytes a way in: an object or an array under `content` would be
// marshalled whole into the very line the record promises holds a size — and
// summariseArgs runs on the arguments of any call, including one naming a tool
// that does not exist, so nothing upstream has checked the shape either (F-D49).
func TestArgumentSummarySizesContentWhateverShapeItArrivesIn(t *testing.T) {
	body := strings.Repeat("secret", 200)
	got := summariseArgs(json.RawMessage(`{"content":{"smuggled":"` + body + `"}}`))
	if strings.Contains(got, "secret") {
		t.Errorf("an object under content was written into the record verbatim:\n%s", got)
	}
	// 1200 bytes of body inside {"smuggled":"…"}, which is 15 bytes of JSON.
	if got != "content=<1215 bytes>" {
		t.Errorf("got %q, want the object recorded by its size", got)
	}

	got = summariseArgs(json.RawMessage(`{"stdin":["one","two"]}`))
	if strings.Contains(got, "one") {
		t.Errorf("an array under stdin was written into the record verbatim:\n%s", got)
	}
	if got != "stdin=<13 bytes>" {
		t.Errorf("got %q, want the array recorded by its size", got)
	}

	// A number is not content in any useful sense, but the rule is about the
	// key: a reader who sees `data=` in a record is told a size, always, rather
	// than being told a size on the calls where the caller happened to send one.
	if got := summariseArgs(json.RawMessage(`{"data":12345}`)); got != "data=<5 bytes>" {
		t.Errorf("got %q, want the number recorded by its size", got)
	}
}

// The size of a record line is not the caller's to choose.
//
// A tool call is written before anything has decided whether the tool exists,
// out of a frame that may be proto.MaxMCPLine — 16 MiB — while every reader of
// the chain stops at 8 MiB: recorder.Verify, recorder.Read and `kelyfos log`'s
// replay all scan with that bound, and recorder.Append has no size guard to
// stop the writer reaching it. A line past it is not a truncated line, it is a
// chain that ends there: `kelyfos verify` gets a scanner error and every event
// after the offending one goes unread with it. Which makes it the one denial of
// service this product cannot shrug off — durable, cheap, and aimed at the one
// artifact it asks people to trust.
func TestOneCallCannotWriteALineTheChainsReadersRefuse(t *testing.T) {
	huge := strings.Repeat("A", 9<<20)
	for _, tc := range []struct {
		where  string
		params mcp.CallToolParams
	}{
		{"under an argument key no tool declares", mcp.CallToolParams{
			Name:      "sandbox_exec",
			Arguments: json.RawMessage(`{"x":{"a":"` + huge + `"}}`),
		}},
		{"in the tool name", mcp.CallToolParams{
			Name: huge,
		}},
		{"in the sandbox id", mcp.CallToolParams{
			Name:      "sandbox_exec",
			Arguments: json.RawMessage(`{"sandbox":"` + huge + `"}`),
		}},
	} {
		t.Run(tc.where, func(t *testing.T) {
			root := t.TempDir()
			rec, err := recorder.Open(root, "0badcafe")
			if err != nil {
				t.Fatal(err)
			}
			s := &hostServer{auditID: "0badcafe", audit: rec}
			s.auditCall(&tc.params)(nil)
			if err := rec.Close(); err != nil {
				t.Fatal(err)
			}

			f, err := os.Open(recorder.Path(root, "0badcafe"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			events, _, err := recorder.Verify(f)
			if err != nil {
				t.Fatalf("the chain cannot be read after one call with nine megabytes %s: %v", tc.where, err)
			}
			if events != 2 {
				t.Errorf("the call and its result are %d events, want 2", events)
			}
		})
	}
}

// Each bound is checked on its own, because the line bound would hide the
// others: an argument that is cut only by the last resort is an argument nobody
// can read next to the rest of the call.
func TestNoOneArgumentCanFillTheLine(t *testing.T) {
	// The default branch. A value the caller wrapped in an object was
	// marshalled whole, with no length to stop at.
	got := summariseArgs(json.RawMessage(`{"x":{"a":"` + strings.Repeat("A", 300) + `"}}`))
	if strings.Count(got, "A") > maxArgBytes {
		t.Errorf("an object argument was written out whole:\n%s", got)
	}
	// 300 bytes of body inside {"a":"…"}, which is 8 bytes of JSON.
	if !strings.Contains(got, "(308 bytes)") {
		t.Errorf("the truncated object does not say what it was cut from:\n%s", got)
	}

	// The array branch, which grows without any one element being long. Bounded
	// by maxArrayBytes rather than maxArgBytes: an array here is usually the
	// egress allowlist, which is recorded nowhere else, so the budget is
	// deliberately generous and the joined line's own cap is what keeps the
	// record a record (P6-28).
	elems := make([]string, 2000)
	for i := range elems {
		elems[i] = `"a"`
	}
	got = summariseArgs(json.RawMessage(`{"argv":[` + strings.Join(elems, ",") + `]}`))
	if len(got) > maxArrayBytes+64 {
		t.Errorf("a 2000-element array rendered %d characters, which is not a log line:\n%s", len(got), got)
	}
	if !strings.Contains(got, "more)") {
		t.Errorf("the array does not say how many elements it left out:\n%s", got)
	}

	// And the case the budget exists for: a real allowlist survives whole. An
	// earlier bound cut this one short, and its last entry is the only record
	// of a domain the agent asked to reach.
	allow := `{"allow":["registry.npmjs.org","github.com","objects.githubusercontent.com",` +
		`"proxy.golang.org","sum.golang.org","pypi.org","files.pythonhosted.org","deb.debian.org"]}`
	if got := summariseArgs(json.RawMessage(allow)); strings.Contains(got, "more)") {
		t.Errorf("an eight-domain allowlist was cut short:\n%s", got)
	} else if !strings.Contains(got, "deb.debian.org") {
		t.Errorf("the allowlist lost its last entry:\n%s", got)
	}
}

// And the line itself, because nothing bounds how many arguments a call has or
// how long one of their names is: a thousand short arguments pass every
// per-argument cap and are still megabytes.
func TestTheWholeSummaryStaysALine(t *testing.T) {
	parts := make([]string, 2000)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"k%04d":"v"`, i)
	}
	got := summariseArgs(json.RawMessage("{" + strings.Join(parts, ",") + "}"))
	if len(got) > maxArgsBytes+64 {
		t.Errorf("2000 short arguments rendered %d characters:\n%.200s…", len(got), got)
	}
	if !strings.Contains(got, "bytes)") {
		t.Errorf("the clipped summary does not say how long the whole thing was:\n%.200s…", got)
	}

	// One long key is the same hole with one argument in it.
	got = summariseArgs(json.RawMessage(`{"` + strings.Repeat("k", 1<<20) + `":1}`))
	if len(got) > maxArgsBytes+64 {
		t.Errorf("a one-megabyte key rendered %d characters", len(got))
	}
}

// Clipping happens on a rune boundary. The summary is marshalled into the line
// that gets hashed and printed to somebody's terminal, and half a character is
// neither — json.Marshal would substitute U+FFFD in the record while the
// terminal showed something else.
func TestClippingNeverLeavesHalfARune(t *testing.T) {
	s := strings.Repeat("€", 10) // three bytes each
	for n := 0; n <= len(s); n++ {
		got := clipUTF8(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("clipping %d bytes of a multi-byte string left %q, which is not valid UTF-8", n, got)
		}
		if len(got) > n {
			t.Fatalf("clipping to %d bytes returned %d", n, len(got))
		}
	}
	// A replacement character the JSON decoder already substituted is a
	// character, and survives the clip like any other.
	if got := clipUTF8("ab�cd", 5); got != "ab�" {
		t.Errorf("got %q, want the replacement character kept", got)
	}
}

// --- F12: guest output in an error message ------------------------------------

// f12Canary is deliberately shaped like the kind of content an Article 17
// request is about, rather than an opaque token: a failing command that
// printed a person's address is the case the record has to be able to erase.
const f12Canary = "CANARY-jane.doe@example.com-guest-stdout"

// failingExecResult is byte-for-byte what host/servemcptools.go's toolExec
// returns for a command that printed f12Canary and exited 2. Built here
// rather than by booting a machine, and kept honest by
// TestF12_TheExecResultFixtureStillMatchesTheTool below — a fixture that has
// drifted from the tool it stands for proves nothing.
func failingExecResult() *mcp.CallToolResult {
	stdout := f12Canary + "\nsecond line\n"
	var text strings.Builder
	text.WriteString(stdout)
	fmt.Fprintf(&text, "\n[exit status %d]", 2)
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.Text(text.String())},
		IsError: true,
		StructuredContent: map[string]any{
			"exit_code": 2, "stdout": stdout, "stderr": "",
		},
	}
}

// TestF12_TheExecResultFixtureStillMatchesTheTool reads the source, because
// the finding is precisely that two files two directories apart disagreed
// about whether a field holds guest content. If sandbox_exec ever stops
// building its result out of the guest's stdout, the fixture above stops
// standing for anything and this test says so.
//
// The exit-status key is the load-bearing half, and the first version of this
// test could not fail on it: it checked two lines resultErrorShape never
// reads, so renaming the structured key to `exitCode` left all three F12 tests
// green while every failing sandbox_exec silently fell through to the
// byte-count branch. It now checks the key resultErrorShape ACTUALLY reads,
// spelled from the constant itself, against the tool that writes it — which is
// a guard that fails when the two drift, and which becomes unnecessary the day
// servemcptools.go uses execExitCodeKey instead of the literal.
func TestF12_TheExecResultFixtureStillMatchesTheTool(t *testing.T) {
	src := readSource(t, "servemcptools.go")
	for _, want := range []string{"text.Write(res.Stdout)", "IsError: res.Code != 0"} {
		if !strings.Contains(src, want) {
			t.Errorf("servemcptools.go no longer contains %q — failingExecResult() no longer "+
				"stands for what sandbox_exec actually returns", want)
		}
	}
	if key := `"` + execExitCodeKey + `":`; !strings.Contains(src, key) {
		t.Errorf("servemcptools.go does not write %s into its structured result, but resultErrorShape "+
			"reads that key: every failing sandbox_exec would fall through to the byte-count branch "+
			"instead of recording its exit status, and nothing else would say so", key)
	}
}

// TestF12_TheExitStatusIsAnExitStatus. resultErrorShape puts a number from the
// tool result straight into the record, so the one thing it must not do is
// format something that is not an exit status as one. +Inf survives
// math.Trunc unchanged and saturates to MaxInt64 on conversion; 1e300 does the
// same.
func TestF12_TheExitStatusIsAnExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    any
		want int
		ok   bool
	}{
		{"an ordinary status", 2, 2, true},
		{"zero", 0, 0, true},
		{"the no-exit-code sentinel", -1, -1, true},
		{"the top of the range", 255, 255, true},
		{"a JSON round trip", float64(2), 2, true},
		{"positive infinity", math.Inf(1), 0, false},
		{"negative infinity", math.Inf(-1), 0, false},
		{"not a number", math.NaN(), 0, false},
		{"far past any exit status", 1e300, 0, false},
		{"above the range", 256, 0, false},
		{"below the sentinel", -2, 0, false},
		{"not whole", 2.5, 0, false},
		{"a string", "2", 0, false},
		{"absent", nil, 0, false},
		{"an object", map[string]any{"exit_code": 2}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := structuredExitCode(tc.v)
			if ok != tc.ok || got != tc.want {
				t.Errorf("structuredExitCode(%v) = (%d, %v), want (%d, %v)", tc.v, got, ok, tc.want, tc.ok)
			}
		})
	}

	// And end to end: a result whose exit_code is nonsense must not produce a
	// line claiming an exit status.
	res := failingExecResult()
	res.StructuredContent = map[string]any{execExitCodeKey: math.Inf(1)}
	if msg := resultErrorShape(res); strings.Contains(msg, "exit status") {
		t.Errorf("resultErrorShape reported %q for an exit_code of +Inf", msg)
	}
}

// TestF12_GuestOutputNeverReachesTheAuditErrorMessage is the source half.
//
// eraseExempt excused error.message as "a system-generated string ... with no
// established precedent for holding raw guest content". The precedent was two
// files away: sandbox_exec builds its tool result out of res.Stdout, and this
// lane stored the first line of it as the error. Every failed command in a
// serve-mcp session left its first line of output in the record.
//
// The audit lane cannot tell a host-written refusal from a guest's stdout —
// both arrive as Content[0].Text — so it must copy neither. What it records
// instead is the shape of the failure: the exit status the guest process
// returned, which is a number the record already keeps on command.exit, or
// failing that the size of the content it declined to hold, which is the rule
// summariseArgs already applies to every argument on every tool.
func TestF12_GuestOutputNeverReachesTheAuditErrorMessage(t *testing.T) {
	root := t.TempDir()
	const id = "0badcafe"
	rec, err := recorder.Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	s := &hostServer{auditID: id, audit: rec}
	if err := rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Reason: recorder.ReasonServeMCP,
	}); err != nil {
		t.Fatal(err)
	}
	p := &mcp.CallToolParams{
		Name:      "sandbox_exec",
		Arguments: json.RawMessage(`{"sandbox":"0badcafe","command":"/usr/bin/report-address"}`),
	}
	s.auditCall(p)(failingExecResult())
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	blob, err := os.ReadFile(recorder.Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), f12Canary) {
		t.Fatalf("a failing command's stdout is in the audit chain:\n%s", blob)
	}

	events, err := recorder.Read(strings.NewReader(string(blob)))
	if err != nil {
		t.Fatal(err)
	}
	var result *recorder.Event
	for i := range events {
		if events[i].Type == recorder.TypeMCPHostResult {
			result = &events[i]
		}
	}
	if result == nil {
		t.Fatal("no mcp.host.result was recorded")
	}
	if result.Outcome != "error" || result.Error == nil || result.Error.Kind != "tool" {
		t.Fatalf("the failure is no longer recorded as one: %+v", result)
	}
	// The record still says what happened, in the terms the record already
	// uses elsewhere for the same fact.
	if result.Error.Message != "exit status 2" {
		t.Errorf("error.message = %q, want the exit status the record already keeps on command.exit", result.Error.Message)
	}
}

// TestF12_AnErasureFingerprintsErrorMessage is the sink half, and it is the
// half that has to hold whatever any future writer of this field does. The
// finding names a second source this task does not own — host/exec.go copies
// the guest supervisor's own error string, which carries the agent-chosen
// path — so the sink is what stops the next one drifting in.
//
// A message is planted directly here, the way host/exec.go plants one, rather
// than through the audit lane: with the source half fixed the lane no longer
// produces one, and a sink test that depends on the source being broken tests
// nothing once it is fixed.
func TestF12_AnErasureFingerprintsErrorMessage(t *testing.T) {
	root := t.TempDir()
	const id = "0badf00d"
	rec, err := recorder.Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []recorder.Event{
		{Type: recorder.TypeSessionStart, Reason: recorder.ReasonServeMCP},
		{Type: recorder.TypeCommandExit, Call: "c1", Error: &recorder.EvError{
			Kind: "internal", Message: `exec: "/tmp/` + f12Canary + `": executable file not found in $PATH`,
		}},
		{Type: recorder.TypeSessionEnd, Reason: "shutdown"},
	} {
		if err := rec.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := recorder.Erase(root, id, "GDPR Article 17 request"); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	blob, err := os.ReadFile(recorder.Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), f12Canary) {
		t.Fatalf("an erasure left the content of error.message behind:\n%s", blob)
	}
	events, err := recorder.Read(strings.NewReader(string(blob)))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Type != recorder.TypeCommandExit {
			continue
		}
		if e.Error == nil {
			t.Fatal("the erasure removed the error object rather than fingerprinting its message")
		}
		if e.Error.Kind != "internal" {
			t.Errorf("error.kind = %q — a fixed enumeration is structural and must survive", e.Error.Kind)
		}
		if !strings.Contains(e.Error.Message, "erased") || !strings.Contains(e.Error.Message, "sha256:") {
			t.Errorf("error.message = %q, want a fingerprint of what was there", e.Error.Message)
		}
	}
}
