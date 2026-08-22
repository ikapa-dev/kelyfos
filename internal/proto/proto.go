// Package proto implements the KelyfOS host/guest wire format defined in
// docs/protocol.md. Both ends of every channel use this package, so the
// protocol has exactly one definition and the two sides cannot drift.
package proto

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Version is the protocol version carried by every message (docs/protocol.md §4).
const Version = 1

// Ports. The range encodes direction: 100xx means the guest listens and the
// host connects through the vsock UDS; 101xx means the host listens on a Unix
// socket and the guest dials out to CID 2 (docs/protocol.md §2).
const (
	PortExec    = 10001 // host -> guest
	PortMCP     = 10002 // host -> guest
	PortControl = 10003 // host -> guest
	PortReady   = 10100 // guest -> host
	PortEvents  = 10101 // guest -> host
)

// CIDs fixed by the virtio-vsock specification and by KelyfOS.
const (
	CIDHost  = 2 // VMADDR_CID_HOST — what guest code connects to
	CIDGuest = 3 // set per VM via the Firecracker vsock resource's guest_cid
)

// Framing limits (docs/protocol.md §3). MaxLine bounds what a reader will
// buffer, so a command that writes megabytes to stdout cannot exhaust memory on
// the other side; MaxChunk bounds what a writer emits before encoding, leaving
// room for base64's 4/3 expansion and the surrounding JSON.
const (
	MaxLine  = 1 << 20 // 1 MiB
	MaxChunk = 64 << 10
)

// ErrLineTooLong is returned when a peer sends a frame beyond MaxLine.
var ErrLineTooLong = errors.New("proto: frame exceeds maximum line length")

// Error is the single error shape used across every channel (§4).
type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Kind + ": " + e.Message }

// Error kinds. Anything reported to the host is one of these.
const (
	ErrBadRequest = "bad_request"
	ErrNotFound   = "not_found"
	ErrDenied     = "denied"
	ErrTimeout    = "timeout"
	ErrKilled     = "killed"
	ErrIO         = "io"
	ErrInternal   = "internal"
)

// ExecRequest is one command, sent by the host on the exec channel (§5.2).
type ExecRequest struct {
	V         int               `json:"v"`
	ID        string            `json:"id"`
	Cmd       []string          `json:"cmd"`
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Stdin     string            `json:"stdin,omitempty"` // base64
	TimeoutMS int64             `json:"timeout_ms,omitempty"`
}

// Stream names on an exec response frame.
const (
	StreamStdout = "stdout"
	StreamStderr = "stderr"
	StreamExit   = "exit"
)

// ExecResponse is one output chunk or the single terminating exit frame (§5.2).
type ExecResponse struct {
	V      int    `json:"v"`
	ID     string `json:"id"`
	Stream string `json:"stream"`
	Data   string `json:"data,omitempty"` // base64, stdout/stderr only
	Code   *int   `json:"code,omitempty"` // exit only
	Signal string `json:"signal,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// Ready and Heartbeat travel on the guest-initiated ready channel (§5.3). The
// host times the arrival of Ready itself and never trusts the guest's clock,
// which before a post-restore resync may be arbitrarily wrong.
type Ready struct {
	V           int    `json:"v"`
	Type        string `json:"type"` // "ready"
	BootID      string `json:"boot_id"`
	Arch        string `json:"arch"`
	Kernel      string `json:"kernel"`
	Supervisor  string `json:"supervisor"`
	MonotonicNS int64  `json:"monotonic_ns"`
	// Overlay reports whether the writable overlay was established over the
	// read-only root. False means the guest is running degraded on a read-only
	// filesystem — diagnosable rather than mysteriously broken.
	Overlay bool `json:"overlay"`
}

type Heartbeat struct {
	V        int    `json:"v"`
	Type     string `json:"type"` // "heartbeat"
	UptimeMS int64  `json:"uptime_ms"`
}

// ControlRequest and ControlResponse are the lifecycle RPCs (§5.4).
type ControlRequest struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	Op         string `json:"op"`
	RealtimeNS int64  `json:"realtime_ns,omitempty"`
	Entropy    string `json:"entropy,omitempty"` // base64
}

type ControlResponse struct {
	V     int    `json:"v"`
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error *Error `json:"error,omitempty"`
}

// Control operations.
const (
	OpPing     = "ping"
	OpShutdown = "shutdown"
	OpResync   = "resync"
)

// Writer emits newline-delimited JSON. Callers must not share one across
// goroutines without their own locking.
type Writer struct{ w io.Writer }

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// Write marshals v and appends the delimiting newline. encoding/json escapes
// any newline inside a string value as \n, two characters on the wire, so the
// "MUST NOT contain embedded newlines" rule holds for free.
func (p *Writer) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal: %w", err)
	}
	if len(b)+1 > MaxLine {
		return ErrLineTooLong
	}
	b = append(b, '\n')
	_, err = p.w.Write(b)
	return err
}

// Reader reads newline-delimited JSON with a hard bound on line length.
type Reader struct{ s *bufio.Scanner }

func NewReader(r io.Reader) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), MaxLine)
	return &Reader{s: s}
}

// Read decodes the next frame into v. It returns io.EOF at end of stream and
// ErrLineTooLong if the peer exceeded the frame limit, which the caller should
// treat as fatal for that connection.
func (p *Reader) Read(v any) error {
	for {
		if !p.s.Scan() {
			if err := p.s.Err(); err != nil {
				if errors.Is(err, bufio.ErrTooLong) {
					return ErrLineTooLong
				}
				return err
			}
			return io.EOF
		}
		line := p.s.Bytes()
		// Tolerate CRLF on read; never write it. Skip blank lines (§3).
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if len(line) == 0 {
			continue
		}
		return json.Unmarshal(line, v)
	}
}
