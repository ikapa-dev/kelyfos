package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
