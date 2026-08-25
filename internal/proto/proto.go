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
	"strconv"
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
	PortShell   = 10004 // host -> guest
	PortForward = 10005 // host -> guest
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

// MaxMCPLine is the frame limit on the MCP channels, which is not MaxLine.
//
// MaxLine is right for exec, where nothing arrives whole: output is chunked at
// MaxChunk and reassembled by the reader, so no single frame is large. An MCP
// tool result is not chunked — read_file answers with a whole file on one line
// — and the per-call limit on a file is 8 MiB (supervisor/tools.go). A 1 MiB
// frame there would refuse messages the tools above it promise to carry, and
// the promise or the limit would have to be the thing that gives.
//
// Sixteen was chosen to leave room for JSON escaping around eight, and that
// arithmetic no longer holds. Since the structuredContent rule of E4-8, a
// read_file result carries the file twice: once in the text block and once as
// `content`, because a client is entitled to prefer either (supervisor/tools.go).
// A file at the 8 MiB cap is therefore 16,777,216 bytes of payload — this
// constant exactly — before the JSON around it and before a single escape. The
// size that first fails cannot be written down as one number, because it
// depends on what escaping that particular text costs: a newline is two bytes
// escaped, and a control character — or a <, > or &, which encoding/json
// escapes too — is six.
//
// That is answered where the frame is written rather than by raising this
// number, because the number is what bounds an untrusted far side: this channel
// crosses the wall, and the far side is not trusted to be reasonable about how
// much it sends. The guest's MCP session treats ErrLineTooLong as the one send
// failure that is not a dead connection — Write below marshals and measures
// before it writes anything, so none of the refused frame reached the wire and
// the stream is still on a frame boundary — and answers the same request in its
// place with a bounded refusal naming the size of the answer and this limit: a
// tool error for a tools/call, a JSON-RPC error for anything else
// (supervisor/mcp.go). What the caller does not get is the guest naming its own
// 8 MiB per-call limit, which a file at or under the cap never reaches.
//
// What does still hold is the part framing depends on: every MCP reader and
// writer on both sides uses this one constant, so there is one answer to "how
// big can a message be" rather than one per file, and no writer can send what
// the reader opposite it will refuse (docs/protocol.md §3).
const MaxMCPLine = 16 << 20

// MaxTeamBody and MaxTeamID are what make a team message that fits on the way
// in still fit on the way out.
//
// MaxLine bounds a frame, and until now it was the only thing bounding either
// direction of the team channel — which is not one budget on one set of bytes,
// because the frame that delivers a message is not the frame that sent it. A
// delivered `recv` carries `from` where the `ask` carried `to`, plus `ok`, plus
// the `correlate` tag a reply has to quote back. The delivery frame is
// therefore tens of bytes larger than the frame that fitted, and by exactly how
// many depends on the two agents' names and on the ids the two guests chose —
// so it cannot be written down as a constant, and a limit that has to be
// recomputed per message is a limit nobody can state.
//
// A band of payload sizes was the result: sizes an agent could send, that the
// broker accepted and recorded as delivered, and that could then never be
// written to the agent they were addressed to. Broker.Recv takes the message
// off the mailbox before the frame is built, so the failed write destroyed it,
// and the write failure was read as a dead connection and closed the channel.
// The recipient got an unexplained EOF for a message it never saw (M-8).
//
// So the payload is bounded below the frame, with the envelope's worst case
// reserved rather than estimated: every field a body-carrying answer can also
// carry, the JSON around them, and the delimiting newline. A kilobyte is far
// more than that costs — roughly sixty bytes of punctuation, a name of at most
// 64 (internal/team ValidAgentName), a tag, and an id — and it stays true when
// an id arrives as control characters, which encoding/json escapes to six bytes
// each. proto_test.go builds that worst case and writes it rather than
// multiplying it out here.
//
// The exec path has had this invariant from the beginning: MaxChunk is the same
// idea one channel over, and it is checked the same way.
const (
	// MaxTeamBody is the largest payload one team message may carry, counted
	// before base64, so that the answer delivering it always fits MaxLine.
	MaxTeamBody = (MaxLine - maxTeamEnvelope) / 4 * 3
	// MaxTeamID bounds the request id the host echoes onto its answer. A guest
	// picks its own ids, and an echoed id is part of the frame the answer has
	// to fit in, so an unbounded one would leave the bound above unprovable.
	MaxTeamID = 128

	// maxTeamEnvelope is what is reserved for everything on a team frame that
	// is not the body.
	maxTeamEnvelope = 1 << 10
)

// ErrLineTooLong is returned when a peer sends a frame beyond MaxLine.
var ErrLineTooLong = errors.New("proto: frame exceeds maximum line length")

// ErrBlankFlood is returned when a peer sends nothing but blank lines. A frame
// is what this reader waits for; a peer that never sends one is not slow, it is
// answering with silence in a form that costs it nothing.
var ErrBlankFlood = errors.New("proto: peer sent only blank lines")

// Error is the single error shape used across every channel (§4).
type Error struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// Error renders the two fields through SafeText, because both came from the
// other end of a channel and this string is printed on somebody's terminal.
//
// A guest answering with "\x1b[1A\x1b[2K\r" moves the cursor up a line and
// erases it, and what it erases is whatever the host printed immediately
// before — on the trust-anchor path, the line saying the sandbox is ready and
// which walls were around it. The guest got to choose what the operator saw
// about the guest.
//
// Found while building a stub for the OpTrust fixture rather than by the audit
// that prompted it (P6-22). SafeText already existed for exactly this and was
// applied on other paths; it is applied here, at the one place every one of
// them formats a guest's error, rather than at each caller — a rule enforced in
// six places is a rule with six chances to be forgotten.
func (e *Error) Error() string { return SafeText(e.Kind) + ": " + SafeText(e.Message) }

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
	// Profile describes the confinement every process the supervisor spawns is
	// given: the flavor it came from, the trees it may write, and the syscalls
	// it is refused (P5-3). Empty on an image older than v0.9.
	Profile string `json:"profile,omitempty"`
	// ProfileError is why that confinement could not be established, when it
	// could not. Non-empty means the guest is running without the profile, and
	// the host refuses such a machine rather than letting it look like a
	// confined one — a limit that is quietly not applied is worse than no
	// limit, because somebody is relying on it (docs/hardening.md §4.3).
	ProfileError string `json:"profile_error,omitempty"`
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

	// plugin.call and plugin.crash (E4-7). Name is the declared plugin, which
	// is the host's name for it and never the one the plugin announces about
	// itself (F-D24).
	Name       string `json:"name,omitempty"`
	Tool       string `json:"tool,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Message    string `json:"message,omitempty"`
	// Args is the redacted summary of what the tool was asked for, in the same
	// shape the outward door records: every key, with anything carrying content
	// replaced by its size.
	Args string `json:"args,omitempty"`
}

// Guest event types. Deliberately the same strings the flight recorder uses:
// the guest is reporting an event of that type, not a private encoding of one.
const (
	GuestEventOOM         = "resource.oom"
	GuestEventPluginCall  = "plugin.call"
	GuestEventPluginCrash = "plugin.crash"
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
	Image     string `json:"image,omitempty"`
	TimeoutMS int64  `json:"timeout_ms,omitempty"`
}

type TeamResponse struct {
	V     int      `json:"v"`
	ID    string   `json:"id"`
	OK    bool     `json:"ok"`
	From  string   `json:"from,omitempty"`
	Body  string   `json:"body,omitempty"` // base64
	Peers []string `json:"peers,omitempty"`
	// Agent names the worker a spawn produced — and, on a peers reply, the
	// agent the host considers the asker to be. The guest prefers this to its
	// own kernel-command-line name, which a fork inherits from its template
	// (E2-9).
	Agent string `json:"agent,omitempty"`
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
	OpTeamSpawn    = "spawn"
)

// Team error kinds, in addition to the shared ones above. Every refusal reaches
// the calling agent as one of these rather than as a silence (docs/teams.md
// §3.8).
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
	// Profile and ProfileError are the guest's confinement, the same pair the
	// ready frame carries. They are on the control response as well because a
	// restored machine never sends a ready frame — it was already running when
	// its memory was written to disk — and the host has to be able to ask a
	// machine it did not boot (P5-7, D32). Empty on a guest older than v0.9,
	// which is the case that matters: it means no confinement, not no answer.
	Profile      string `json:"profile,omitempty"`
	ProfileError string `json:"profile_error,omitempty"`
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
type Writer struct {
	w   io.Writer
	max int
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w, max: MaxLine} }

// NewWriterLimit is NewWriter with a frame limit of the caller's choosing, and
// it has to be the same number the far side's reader was given: a writer that
// will send more than a reader will accept is a connection that dies mid-answer,
// which is what a caller sees as an unexplained EOF.
func NewWriterLimit(w io.Writer, max int) *Writer { return &Writer{w: w, max: max} }

// Write marshals v and appends the delimiting newline. encoding/json escapes
// any newline inside a string value as \n, two characters on the wire, so the
// "MUST NOT contain embedded newlines" rule holds for free.
func (p *Writer) Write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("proto: marshal: %w", err)
	}
	if len(b)+1 > p.max {
		return ErrLineTooLong
	}
	b = append(b, '\n')
	_, err = p.w.Write(b)
	return err
}

// Reader reads newline-delimited JSON with a hard bound on line length.
type Reader struct{ s *bufio.Scanner }

func NewReader(r io.Reader) *Reader { return NewReaderLimit(r, MaxLine) }

// NewReaderLimit is NewReader with a frame limit of the caller's choosing. The
// MCP channels use it with MaxMCPLine; nothing else should need it.
func NewReaderLimit(r io.Reader, max int) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64<<10), max)
	return &Reader{s: s}
}

// Read decodes the next frame into v. It returns io.EOF at end of stream and
// ErrLineTooLong if the peer exceeded the frame limit, which the caller should
// treat as fatal for that connection.
// maxBlankLines bounds how long one Read will keep skipping nothing.
//
// Blank lines are tolerated because §3 says they are, and skipping them is
// right. Skipping them without a bound is not: a sender writing "\n" forever
// keeps a single Read spinning inside its own loop, so a caller that wanted to
// budget frames between calls never gets control back to do it. That is below
// every channel built on this reader rather than in any one of them (M-9).
//
// The number is far above any run of blank lines a writer produces — this
// package's own Writer emits none — so reaching it means the other end is
// sending nothing on purpose.
const maxBlankLines = 1024

func (p *Reader) Read(v any) error {
	blanks := 0
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
			blanks++
			if blanks > maxBlankLines {
				return ErrBlankFlood
			}
			continue
		}
		return json.Unmarshal(line, v)
	}
}

// SafeText renders a string that came from a guest so it cannot forge a line.
//
// Everything a guest sends is a guest's choice of bytes, and several of those
// strings are printed to a terminal or written into the record and rendered
// later: a profile name on the boot line, an OOM victim's process name, a tool
// argument. A control character in one of those is not a display nuisance — it
// is the guest deciding what the host's output looks like. The boot line is the
// sharpest case, because it is where a person reads which walls are around
// their sandbox, and an escape sequence can rewrite a line that has already
// been printed.
//
// Ordinary strings come back untouched, so nothing that was already fine
// changes; only a string that could break a line is quoted, and then it is
// visibly quoted.
//
// One copy on purpose. Three had appeared by the end of P6-3 — in the host's
// audit summariser, the supervisor's, and here — which is how the same class of
// bug turned up three times in one task.
func SafeText(s string) string {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return strconv.Quote(s)
		}
	}
	return s
}
