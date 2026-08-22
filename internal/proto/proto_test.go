package proto

import (
	"bytes"
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
