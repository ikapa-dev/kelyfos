package proto

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// The shell channel is the one place this protocol is not newline-delimited
// JSON, so its framing is the thing to pin: a length prefix that cannot be
// trusted cannot be resynchronised from, and a terminal stream that loses its
// alignment is a terminal that never works again.

func TestShellFramesRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	// Bytes that would be mangled by anything text-shaped: a NUL, a newline, and
	// something that is not valid UTF-8.
	payload := []byte{0x00, '\n', 0xff, 'a'}
	if err := WriteShellFrame(&buf, ShellData, payload); err != nil {
		t.Fatal(err)
	}
	if err := WriteShellControl(&buf, ShellResize{Op: "resize", Cols: 132, Rows: 40}); err != nil {
		t.Fatal(err)
	}

	kind, got, err := ReadShellFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if kind != ShellData || !bytes.Equal(got, payload) {
		t.Errorf("data frame came back as kind %d, %v", kind, got)
	}
	kind, got, err = ReadShellFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if kind != ShellControl || !strings.Contains(string(got), `"cols":132`) {
		t.Errorf("control frame came back as kind %d, %s", kind, got)
	}
}

// An empty data frame is legal — a terminal read can return nothing — and must
// not be confused with the end of the stream.
func TestAnEmptyFrameIsNotTheEnd(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteShellFrame(&buf, ShellData, nil); err != nil {
		t.Fatal(err)
	}
	if err := WriteShellFrame(&buf, ShellData, []byte("after")); err != nil {
		t.Fatal(err)
	}
	if _, got, err := ReadShellFrame(&buf); err != nil || len(got) != 0 {
		t.Fatalf("empty frame: %v %v", got, err)
	}
	if _, got, err := ReadShellFrame(&buf); err != nil || string(got) != "after" {
		t.Fatalf("the frame after an empty one: %q %v", got, err)
	}
}

// A length the far side cannot be trusted about is fatal to the connection,
// because there is nowhere to resynchronise to.
func TestAnImpossibleLengthEndsTheConnection(t *testing.T) {
	head := []byte{ShellData, 0xff, 0xff, 0xff, 0xff}
	_, _, err := ReadShellFrame(bytes.NewReader(head))
	if err == nil {
		t.Fatal("a frame claiming 4 GiB was accepted")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the error does not say what the limit is: %v", err)
	}
	// And a kind nobody defined is refused rather than guessed at.
	if _, _, err := ReadShellFrame(bytes.NewReader([]byte{9, 0, 0, 0, 0})); err == nil {
		t.Error("an unknown frame kind was accepted")
	}
	// A writer refuses to send more than a reader will take, so the two limits
	// cannot disagree.
	if err := WriteShellFrame(io.Discard, ShellData, make([]byte, MaxShellFrame+1)); err == nil {
		t.Error("a frame over the limit was written")
	}
}

// A truncated frame is an error rather than a short read: half a keystroke is
// not a keystroke.
func TestATruncatedFrameIsAnError(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteShellFrame(&buf, ShellData, []byte("hello"))
	short := buf.Bytes()[:7] // header plus two of five bytes
	if _, _, err := ReadShellFrame(bytes.NewReader(short)); err == nil {
		t.Fatal("a truncated frame was accepted")
	}
}
