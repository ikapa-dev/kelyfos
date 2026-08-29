package proto

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// The forward channel (E5-5, docs/qol.md §4).
//
// One vsock connection carries one forwarded TCP connection. The host binds a
// listener on its own loopback, and every connection it accepts becomes a
// connection here, opened with a single line of JSON naming the guest port and
// answered with a single line saying whether anything was listening. After
// those two lines the connection is the bytes, in both directions, with no
// framing at all — because a TCP bridge that framed its payload would be
// re-implementing TCP inside TCP.
//
// The whole point of this channel is what it is *not*: no packet crosses the
// TAP in either direction, so the nftables ruleset that makes the network
// egress-only is untouched by a forward, and `nft list ruleset` looks the same
// with one as without (F-D7).

// MaxForwardLine bounds the two handshake lines. They carry a port and a
// sentence, and anything larger is a client that is not speaking this protocol.
const MaxForwardLine = 4 << 10

// ForwardOpen is the host's first and only request: which guest-local port to
// connect this to.
type ForwardOpen struct {
	V    int    `json:"v"`
	Op   string `json:"op"` // "open"
	Port int    `json:"port"`
}

// ForwardReply is the guest's answer, sent before any payload. A refusal here
// is almost always the same thing — nothing is listening on that port inside
// the sandbox — and saying so is the difference between a forward that looks
// broken and one that tells you the server has not started yet.
type ForwardReply struct {
	V     int    `json:"v"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// WriteForwardOpen sends the open request.
func WriteForwardOpen(w io.Writer, port int) error {
	blob, err := json.Marshal(ForwardOpen{V: Version, Op: "open", Port: port})
	if err != nil {
		return err
	}
	_, err = w.Write(append(blob, '\n'))
	return err
}

// ReadForwardOpen reads the open request off r, which the caller must keep
// using afterwards: a buffered reader will already hold the first bytes of the
// stream, and reading them twice is how a forward loses its first packet.
func ReadForwardOpen(r *bufio.Reader) (ForwardOpen, error) {
	var open ForwardOpen
	line, err := readForwardLine(r)
	if err != nil {
		return open, err
	}
	if err := json.Unmarshal(line, &open); err != nil {
		return open, fmt.Errorf("proto: forward open is not JSON: %w", err)
	}
	if open.Op != "open" {
		return open, fmt.Errorf("proto: first forward frame is %q, not an open", open.Op)
	}
	if open.Port < 1 || open.Port > 65535 {
		return open, fmt.Errorf("proto: forward open names port %d", open.Port)
	}
	return open, nil
}

// WriteForwardReply answers an open. An empty msg means it succeeded.
func WriteForwardReply(w io.Writer, msg string) error {
	blob, err := json.Marshal(ForwardReply{V: Version, OK: msg == "", Error: msg})
	if err != nil {
		return err
	}
	_, err = w.Write(append(blob, '\n'))
	return err
}

// ReadForwardReply reads the answer, with the same rule about r as
// ReadForwardOpen.
func ReadForwardReply(r *bufio.Reader) (ForwardReply, error) {
	var reply ForwardReply
	line, err := readForwardLine(r)
	if err != nil {
		return reply, err
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		return reply, fmt.Errorf("proto: forward reply is not JSON: %w", err)
	}
	// The same edge rule every other guest->host frame gets, applied here
	// rather than through Reader.Read because this channel does its own
	// framing (P7-17/F20, second review round). Error is the guest's own
	// sentence and host/forward.go:181 puts it straight into the flight
	// recorder's Reason field, so it is cleaned before it is either recorded or
	// shown.
	reply.Sanitize()
	return reply, nil
}

// Sanitize is Sanitizer for the forward channel's reply. Error is the only
// string the guest chooses here, and it is the one that reaches the record.
func (r *ForwardReply) Sanitize() { r.Error = SafeText(r.Error) }

func readForwardLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if err == bufio.ErrBufferFull || len(line) > MaxForwardLine {
		return nil, fmt.Errorf("proto: forward handshake line over %d bytes", MaxForwardLine)
	}
	if err != nil {
		return nil, err
	}
	return line, nil
}
