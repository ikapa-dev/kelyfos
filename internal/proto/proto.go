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
	PortTeam    = 10102 // guest -> host
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

// GuestEvent is one guest-originated report on the events channel (§5.5).
//
// The guest reports facts and nothing else: it does not number these, stamp
// them, or chain them. The host writes the flight recorder, because a guest
// that could forge chain links could forge its own audit trail (docs/events.md
// §1). MonotonicNS is the guest's own clock and is carried for ordering within
// the guest, never as the event's timestamp.
type GuestEvent struct {
	V           int    `json:"v"`
	Type        string `json:"type"`
	MonotonicNS int64  `json:"monotonic_ns,omitempty"`

	// resource.oom
	PID    int    `json:"pid,omitempty"`
	Comm   string `json:"comm,omitempty"`
	RSSKiB int64  `json:"rss_kib,omitempty"`
}

// Guest event types. Deliberately the same strings the flight recorder uses:
// the guest is reporting an event of that type, not a private encoding of one.
const (
	GuestEventOOM = "resource.oom"
)

// TeamRequest and TeamResponse are the team broker's RPCs (§5.6), and they run
// guest → host for a reason worth stating: every other channel in this protocol
// exists because the host wants something from the guest, and this one exists
// because an agent inside the guest wants to reach another agent. Nothing
// already here can carry that — `ready` and `events` are one-way reports, and
// `exec`, `mcp` and `control` are all the host calling in.
//
// The host is the only participant that can answer, because the host is the
// only participant that knows the edge list, holds the other guests' channels,
// and writes the audit record. A guest asks; it is never asked to route.
type TeamRequest struct {
	V    int    `json:"v"`
	ID   string `json:"id"`
	Op   string `json:"op"`
	To   string `json:"to,omitempty"`
	Body string `json:"body,omitempty"` // base64
	// Correlate names the ask a reply answers. The guest echoes what the broker
	// gave it and cannot invent one: a reply whose correlation the broker does
	// not recognise is refused, so a guest cannot answer a question nobody asked
	// it and reach an agent it has no edge to that way.
	Correlate string `json:"correlate,omitempty"`
	Key       string `json:"key,omitempty"`
	TimeoutMS int64  `json:"timeout_ms,omitempty"`
}

type TeamResponse struct {
	V     int      `json:"v"`
	ID    string   `json:"id"`
	OK    bool     `json:"ok"`
	From  string   `json:"from,omitempty"`
	Body  string   `json:"body,omitempty"` // base64
	Peers []string `json:"peers,omitempty"`
	// Correlate on a delivered question is the tag a reply must carry back.
	Correlate string `json:"correlate,omitempty"`
	Error     *Error `json:"error,omitempty"`
}

// Team operations, matching the MCP tools E2-2 exposes one for one.
const (
	OpTeamSend     = "send"
	OpTeamRecv     = "recv"
	OpTeamAsk      = "ask"
	OpTeamReply    = "reply"
	OpTeamPeers    = "peers"
	OpTeamStoreGet = "store_get"
	OpTeamStorePut = "store_put"
)

// Team error kinds, in addition to the shared ones above. Every refusal reaches
// the calling agent as one of these rather than as a silence (docs/teams.md
// §3.6).
const (
	ErrNoEdge      = "no_edge"
	ErrNoSuchAgent = "no_such_agent"
	ErrUnreachable = "unreachable"
)

// ControlRequest and ControlResponse are the lifecycle RPCs (§5.4).
type ControlRequest struct {
	V          int    `json:"v"`
	ID         string `json:"id"`
	Op         string `json:"op"`
	RealtimeNS int64  `json:"realtime_ns,omitempty"`
	Entropy    string `json:"entropy,omitempty"` // base64
	// CAPEM carries the egress CA's trust anchor for OpTrust. It is a public
	// certificate, never a key — the guest is asked to trust the proxy, not
	// given the means to impersonate it.
	CAPEM string `json:"ca_pem,omitempty"`
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
	// OpTrust installs the egress CA's anchor in the guest trust store. It
	// arrives after boot rather than in the image because the CA is minted per
	// run and never persisted (decision D6), and after the overlay is up
	// because the rootfs itself is read-only.
	OpTrust = "trust"
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
