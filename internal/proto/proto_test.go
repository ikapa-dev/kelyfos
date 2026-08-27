package proto

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestWriteReadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	code := 0
	want := ExecResponse{V: Version, ID: "a1", Stream: StreamExit, Code: &code}
	if err := NewWriter(&buf).Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got ExecResponse
	if err := NewReader(&buf).Read(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.ID != want.ID || got.Stream != want.Stream || got.Code == nil || *got.Code != 0 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// A plain JSON string field silently replaces invalid UTF-8 with U+FFFD on
// marshal (encoding/json's documented behavior), which would corrupt an argv
// entry built from arbitrary bytes. EncodeCmd/DecodeCmd exist so ExecRequest.Cmd
// survives that trip exactly, the same way Stdin's base64 already does (F15).
func TestEncodeDecodeCmdRoundTripsNonUTF8Bytes(t *testing.T) {
	// Lone continuation bytes: not valid UTF-8 on their own, and exactly what
	// json.Marshal would otherwise mangle into four U+FFFD characters.
	invalid := []byte{0x80, 0x81, 0x82, 0x83}
	argv := []string{"/bin/sh", "-c", string(invalid)}

	encoded := EncodeCmd(argv)
	if len(encoded) != len(argv) {
		t.Fatalf("EncodeCmd changed argc: got %d elements, want %d", len(encoded), len(argv))
	}
	for _, e := range encoded {
		if !json.Valid([]byte(`"` + e + `"`)) {
			t.Fatalf("encoded element %q is not safe to embed as a plain JSON string", e)
		}
	}

	decoded, err := DecodeCmd(encoded)
	if err != nil {
		t.Fatalf("DecodeCmd: %v", err)
	}
	if len(decoded) != len(argv) {
		t.Fatalf("DecodeCmd changed argc: got %d elements, want %d", len(decoded), len(argv))
	}
	for i := range argv {
		if decoded[i] != argv[i] {
			t.Fatalf("element %d round-tripped to %q, want %q", i, decoded[i], argv[i])
		}
	}
	if decoded[2] != string(invalid) {
		t.Fatalf("non-UTF-8 argument corrupted: got %v, want %v", []byte(decoded[2]), invalid)
	}

	// The full wire path: build the request the way host code does, marshal
	// it as ExecRequest actually travels, and confirm the bytes are still
	// exact on the far side — not replaced with U+FFFD anywhere along the way.
	var buf bytes.Buffer
	req := ExecRequest{V: Version, ID: "t1", Cmd: EncodeCmd(argv)}
	if err := NewWriter(&buf).Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got ExecRequest
	if err := NewReader(&buf).Read(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	gotArgv, err := DecodeCmd(got.Cmd)
	if err != nil {
		t.Fatalf("DecodeCmd after wire round trip: %v", err)
	}
	if gotArgv[2] != string(invalid) {
		t.Fatalf("argument corrupted across the wire: got %v, want %v", []byte(gotArgv[2]), invalid)
	}
}

func TestDecodeCmdRejectsInvalidBase64(t *testing.T) {
	if _, err := DecodeCmd([]string{"not valid base64!!"}); err == nil {
		t.Fatal("expected an error for a non-base64 cmd element")
	}
}

// The framing rule the MCP spec states and every KelyfOS channel inherits:
// one message per line, and no literal newline inside a message.
func TestNoEmbeddedNewlines(t *testing.T) {
	var buf bytes.Buffer
	msg := ExecResponse{V: Version, ID: "a1", Stream: StreamStdout, Data: "line one\nline two"}
	if err := NewWriter(&buf).Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if n := bytes.Count(buf.Bytes(), []byte{'\n'}); n != 1 {
		t.Fatalf("expected exactly one newline (the delimiter), got %d: %q", n, buf.String())
	}
	if !bytes.HasSuffix(buf.Bytes(), []byte{'\n'}) {
		t.Fatal("frame is not newline-terminated")
	}
}

func TestReaderRejectsOversizeLine(t *testing.T) {
	huge := strings.Repeat("x", MaxLine+16)
	r := NewReader(strings.NewReader(huge + "\n"))
	var v map[string]any
	if err := r.Read(&v); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got %v", err)
	}
}

func TestWriterRejectsOversizeFrame(t *testing.T) {
	var buf bytes.Buffer
	msg := ExecResponse{V: Version, ID: "a1", Stream: StreamStdout, Data: strings.Repeat("x", MaxLine)}
	if err := NewWriter(&buf).Write(msg); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got %v", err)
	}
	if buf.Len() != 0 {
		t.Fatal("an oversize frame must not be partially written")
	}
}

func TestReaderToleratesCRLFAndBlankLines(t *testing.T) {
	in := "\r\n\n{\"v\":1,\"id\":\"a1\",\"stream\":\"stdout\",\"data\":\"aGk=\"}\r\n"
	var got ExecResponse
	if err := NewReader(strings.NewReader(in)).Read(&got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.ID != "a1" || got.Data != "aGk=" {
		t.Fatalf("unexpected frame: %+v", got)
	}
}

func TestReaderReturnsEOF(t *testing.T) {
	var v map[string]any
	if err := NewReader(strings.NewReader("")).Read(&v); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// A 64 KiB chunk must still fit a 1 MiB frame after base64 expansion and the
// surrounding JSON — otherwise the writer's own limit would reject its output.
func TestChunkFitsInFrame(t *testing.T) {
	if MaxChunk*4/3+512 >= MaxLine {
		t.Fatalf("MaxChunk %d does not leave room inside MaxLine %d after base64", MaxChunk, MaxLine)
	}
}

// The arithmetic in the MaxMCPLine comment, checked here rather than left to a
// reader to multiply out. A read_file result carries the file twice — once in
// the text block, once as structuredContent — so a file at the guest tools'
// 8 MiB per-call cap is the whole frame budget before the JSON around it, and
// the writer refuses the frame. What the caller gets is the guest's own
// refusal, naming the size and this limit (supervisor/mcp.go) — never its
// per-call limit, which a file at the cap never reaches.
func TestAFileAtTheToolCapNoLongerFitsAnMCPFrame(t *testing.T) {
	const toolCap = 8 << 20 // supervisor/tools.go maxToolBytes
	body := strings.Repeat("x", toolCap)
	text := map[string]any{"type": "text", "text": body}
	structured := map[string]any{"path": "/work/big.txt", "bytes": toolCap, "content": body, "encoding": "utf-8"}
	result := map[string]any{"content": []any{text}, "structuredContent": structured}
	frame := map[string]any{"jsonrpc": "2.0", "id": 1, "result": result}
	var buf bytes.Buffer
	if err := NewWriterLimit(&buf, MaxMCPLine).Write(frame); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("a file at the %d byte tool cap should not fit a %d byte frame, got %v", toolCap, MaxMCPLine, err)
	}
	if buf.Len() != 0 {
		t.Fatal("an oversize frame must not be partially written")
	}
}

// Why the size that first fails cannot be written down as one number: what a
// frame costs depends on the bytes in the file. A newline is two bytes escaped
// and a control character six, and Marshal escapes <, > and & to six as well —
// so a file of HTML or of source crosses the limit sooner than prose does.
func TestEscapingCostsMoreForSomeFilesThanOthers(t *testing.T) {
	for in, want := range map[string]int{"a": 1, "\n": 2, "\x00": 6, "<": 6, ">": 6, "&": 6} {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %q: %v", in, err)
		}
		// Less the two surrounding quotes Marshal adds.
		if got := len(b) - 2; got != want {
			t.Fatalf("%q encodes to %d bytes of JSON, expected %d", in, got, want)
		}
	}
}

// The invariant supervisor/mcp.go depends on when it answers an oversized
// result with a refusal rather than by closing the session: Write marshals and
// measures the whole frame before it writes any of it, so a refused frame
// leaves the stream exactly where it was and the refusal written in its place
// is the next thing the reader opposite sees. Had any part of the refused frame
// gone out, the refusal would arrive glued to a fragment and the reader would
// see one unparseable line instead of two good ones.
func TestARefusedFrameLeavesTheStreamOnAFrameBoundary(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriterLimit(&buf, MaxMCPLine)

	oversize := map[string]any{"jsonrpc": "2.0", "id": 7, "result": strings.Repeat("x", MaxMCPLine)}
	if err := w.Write(oversize); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("expected ErrLineTooLong, got %v", err)
	}

	refusal := map[string]any{"jsonrpc": "2.0", "id": 7, "error": "the result of this call is too large to send"}
	if err := w.Write(refusal); err != nil {
		t.Fatalf("writing the refusal in place of the answer: %v", err)
	}
	if n := bytes.Count(buf.Bytes(), []byte{'\n'}); n != 1 {
		t.Fatalf("expected the refusal alone on the stream, got %d frames: %d bytes", n, buf.Len())
	}

	var got map[string]any
	if err := NewReaderLimit(&buf, MaxMCPLine).Read(&got); err != nil {
		t.Fatalf("reading the refusal back: %v", err)
	}
	if got["error"] != refusal["error"] {
		t.Fatalf("the reader did not get the refusal whole: %+v", got)
	}
}

// The team channel's version of TestChunkFitsInFrame, and the reason it builds
// a frame rather than multiplying one out: on this channel the answer is not
// the request, so "it fitted on the way in" proves nothing about the way out.
//
// This is the largest answer the host can be asked to write — a body at
// MaxTeamBody, an id at MaxTeamID and every byte of it a control character,
// which encoding/json escapes to six, the longest name an agent can have, and a
// correlate tag. It has to fit MaxLine, or there are messages a broker accepts,
// records as delivered, and can then never write to the agent they were
// addressed to (M-8).
//
// The longest name is not ValidAgentName's 64. That is the limit on a *declared*
// name; the broker mints a spawned worker's as `<spawner>-spawn-<n>` without
// passing it back through the check (internal/team spawn.go), and `recv`
// delivers a message from that worker with the minted name as `from`. So the
// worst case is built the way the host builds it, from a spawner already at the
// limit — and the test measures the envelope against what maxTeamEnvelope
// reserves, rather than only asking whether this one frame fits, because the
// reservation is the thing MaxTeamBody is derived from.
func TestTheLargestTeamAnswerStillFitsAFrame(t *testing.T) {
	// b.spawnSeq is an int, so its decimal form is at most the digits of
	// MaxInt64; nothing bounds how many workers one agent spawns over a run.
	worker := strings.Repeat("a", 64) + "-spawn-" + strconv.FormatInt(math.MaxInt64, 10)
	body := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, MaxTeamBody))
	worst := TeamResponse{
		V:         Version,
		ID:        strings.Repeat("\x01", MaxTeamID),
		OK:        true,
		From:      worker,
		Body:      body,
		Correlate: strings.Repeat("f", 64),
	}
	// Everything on the frame that is not the body: what maxTeamEnvelope claims
	// to cover, and what MaxTeamBody is derived from. Measured through
	// encoding/json rather than taken from the frame below, so that it is still
	// a number when the frame limit has already refused to write the answer —
	// an envelope over its reservation is the diagnosis, and a frame that does
	// not fit is only the symptom. A field added to TeamResponse, or a name
	// longer than the spawn path can mint today, lands here.
	blob, err := json.Marshal(worst)
	if err != nil {
		t.Fatal(err)
	}
	if envelope := len(blob) + 1 - len(body); envelope > maxTeamEnvelope { // +1: the delimiter
		t.Fatalf("the envelope of the largest answer is %d bytes against a reservation of %d, "+
			"so MaxTeamBody is no longer derived from anything true", envelope, maxTeamEnvelope)
	}

	var buf bytes.Buffer
	if err := NewWriter(&buf).Write(worst); err != nil {
		t.Fatalf("the largest team answer does not fit a %d byte frame: %v", MaxLine, err)
	}
	if buf.Len() > MaxLine {
		t.Fatalf("the frame is %d bytes, over the %d byte limit", buf.Len(), MaxLine)
	}
}

// Why MaxTeamBody is below MaxLine at all, stated as the measurement it came
// from: the frame that delivers a message is larger than the frame that sent
// it, by a margin that depends on the two agents' names, the two ids, and the
// correlate tag — so it cannot be written down as one number, and a payload
// sized against the sending frame is not safe against the delivering one.
func TestADeliveredTeamMessageIsALargerFrameThanTheOneThatSentIt(t *testing.T) {
	body := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 1024))

	var asked bytes.Buffer
	if err := NewWriter(&asked).Write(TeamRequest{
		V: Version, ID: "17", Op: OpTeamAsk, To: "bob", Body: body, TimeoutMS: 30000,
	}); err != nil {
		t.Fatal(err)
	}
	var delivered bytes.Buffer
	if err := NewWriter(&delivered).Write(TeamResponse{
		V: Version, ID: "17", OK: true, From: "alice", Body: body,
		Correlate: "0123456789abcdef",
	}); err != nil {
		t.Fatal(err)
	}
	if delivered.Len() <= asked.Len() {
		t.Fatalf("the delivering frame is %d bytes and the sending frame %d; if that is now the "+
			"other way round, MaxTeamBody's derivation needs rereading", delivered.Len(), asked.Len())
	}
}
