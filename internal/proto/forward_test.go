package proto

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

// The handshake is two lines and then the bytes. What this checks is the part
// that is easy to get wrong: the reader that consumed the handshake must be the
// reader that carries on, or the first bytes of the stream are read twice and
// thrown away once.
func TestForwardHandshakeLeavesTheStreamIntact(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteForwardOpen(&wire, 80); err != nil {
		t.Fatal(err)
	}
	wire.WriteString("GET / HTTP/1.1\r\nHost: x\r\n\r\n")

	r := bufio.NewReader(&wire)
	open, err := ReadForwardOpen(r)
	if err != nil {
		t.Fatal(err)
	}
	if open.Port != 80 || open.V != Version {
		t.Errorf("open = %+v", open)
	}
	rest, _ := r.ReadString('\n')
	if !strings.HasPrefix(rest, "GET / HTTP/1.1") {
		t.Errorf("the first bytes of the stream were eaten: %q", rest)
	}
}

func TestForwardReplyCarriesTheRefusal(t *testing.T) {
	var wire bytes.Buffer
	if err := WriteForwardReply(&wire, "nothing is listening on port 80"); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadForwardReply(bufio.NewReader(&wire))
	if err != nil {
		t.Fatal(err)
	}
	if reply.OK {
		t.Error("a reply carrying an error says it succeeded")
	}
	if !strings.Contains(reply.Error, "nothing is listening") {
		t.Errorf("reply = %+v", reply)
	}

	wire.Reset()
	if err := WriteForwardReply(&wire, ""); err != nil {
		t.Fatal(err)
	}
	reply, err = ReadForwardReply(bufio.NewReader(&wire))
	if err != nil || !reply.OK {
		t.Errorf("an empty message is success: %+v %v", reply, err)
	}
}

// A port number that cannot be a port, and an opening frame that is not an
// open, are both refused rather than acted on.
func TestForwardOpenIsChecked(t *testing.T) {
	for _, line := range []string{
		`{"v":1,"op":"open","port":0}`,
		`{"v":1,"op":"open","port":70000}`,
		`{"v":1,"op":"resize","port":80}`,
		`not json at all`,
	} {
		r := bufio.NewReader(strings.NewReader(line + "\n"))
		if _, err := ReadForwardOpen(r); err == nil {
			t.Errorf("%s was accepted", line)
		}
	}
}

// An unterminated line does not let a client make the reader buffer without
// bound.
func TestForwardHandshakeIsBounded(t *testing.T) {
	huge := strings.Repeat("a", MaxForwardLine*2)
	r := bufio.NewReaderSize(strings.NewReader(huge), 64)
	if _, err := ReadForwardOpen(r); err == nil {
		t.Error("an unbounded handshake line was accepted")
	}
}
