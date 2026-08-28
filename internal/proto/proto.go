// Package proto implements the KelyfOS host/guest wire format defined in
// docs/protocol.md. Both ends of every channel use this package, so the
// protocol has exactly one definition and the two sides cannot drift.
package proto

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
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
// more than that costs — roughly sixty bytes of punctuation, an agent's name, a
// tag, and an id — and it stays true when an id arrives as control characters,
// which encoding/json escapes to six bytes each. proto_test.go builds that
// worst case and writes it rather than multiplying it out here.
//
// The name is the one part of that this package cannot bound itself, and the
// number to reserve against is not internal/team ValidAgentName's 64. That rule
// is applied to the names a person declares (NewTopology), and a worker an
// agent spawns is not declared: the broker mints it as `<spawner>-spawn-<n>`
// and attaches it to the topology without passing it back through the check
// (internal/team spawn.go), so a declared agent already at 64 bytes has workers
// whose names are longer than any name that check would accept — and `recv`
// delivers them to it as `from`, on a frame that carries a body. The suffix
// cannot nest, because a spawn budget is granted only to the agents in the team
// file (host/team.go) and a worker therefore has none of its own. The longest
// name that can reach this envelope is 64 + "-spawn-" + the digits of an int:
// 90 bytes, and that is the name proto_test.go builds its worst case with.
//
// Measured, that answer's envelope is 983 bytes, so the reservation still holds
// with room to spare — but the reservation is what the test pins rather than
// the arithmetic. It measures the envelope of the largest answer against this
// constant, so a field added here, or a name longer than the spawn path can
// mint today, fails there instead of in a message that was accepted, recorded
// as delivered, and then could not be written.
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

// MalformedFrame wraps a JSON decoding failure for one frame that the scanner
// had already found in full: a complete, newline-terminated line came off the
// wire, and json.Unmarshal simply rejected what was in it (bad JSON, or a
// value shaped wrong for v). Unlike ErrLineTooLong or a genuine I/O failure,
// this leaves the stream exactly where a successful Read would: sitting on the
// next frame's boundary. A caller that can answer with a protocol error is not
// looking at a dead connection and can keep serving past it (supervisor/mcp.go).
type MalformedFrame struct{ Err error }

func (e *MalformedFrame) Error() string { return e.Err.Error() }
func (e *MalformedFrame) Unwrap() error { return e.Err }

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

// Sanitize replaces every string field the far side of a channel chose with
// its SafeText form, in place, and holds Kind to the enumeration below.
// Nil-safe, because an Error is carried as a pointer on every frame that has
// one and is absent on most of them.
//
// The Kind half is P7-17/F20's rider from the record workstream's review.
// internal/recorder/erase.go exempts an event's error kind from erasure as "a
// fixed enumeration", and it was not one: host/exec.go copied the guest's Kind
// verbatim into the chain and nothing checked it — exitCodeFor switches with a
// default, which accepts rather than rejects — so arbitrary guest text sat in a
// field docs/retention.md promises "survives unchanged", and survived an
// erasure verbatim. That is F12's exact shape one field to the left: an
// exemption justified by a property no code enforced. The enumeration lives in
// this file, so the rule that makes it one lives here too, at the same edge
// every other guest string is cleaned at.
//
// A kind that is not one of the seven becomes ErrInternal, and the string the
// guest actually sent moves into Message — which is where guest-chosen prose
// belongs, is the field this path no longer records at all, and is still
// printed on the operator's terminal. Nothing diagnostic is lost; it is moved
// to the field that is allowed to hold it.
func (e *Error) Sanitize() {
	if e == nil {
		return
	}
	e.Kind, e.Message = SafeText(e.Kind), SafeText(e.Message)
	if KnownErrorKind(e.Kind) {
		return
	}
	if e.Kind != "" {
		if e.Message == "" {
			e.Message = e.Kind
		} else {
			e.Message = e.Kind + ": " + e.Message
		}
	}
	e.Kind = ErrInternal
}

// KnownErrorKind reports whether kind is one of the seven this protocol
// defines. Exact: neither case nor surrounding whitespace is forgiven, because
// a field an auditor is told is an enumeration has to be one.
func KnownErrorKind(kind string) bool {
	switch kind {
	case ErrBadRequest, ErrNotFound, ErrDenied, ErrTimeout, ErrKilled, ErrIO, ErrInternal:
		return true
	}
	return false
}

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
	Cmd       []string          `json:"cmd"` // base64, one element per argv entry
	Cwd       string            `json:"cwd,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Stdin     string            `json:"stdin,omitempty"` // base64
	TimeoutMS int64             `json:"timeout_ms,omitempty"`
}

// EncodeCmd and DecodeCmd convert an argv between its in-memory form and the
// base64-per-element form ExecRequest.Cmd carries on the wire.
//
// encoding/json marshals a Go string as UTF-8 and silently replaces any byte
// sequence that is not valid UTF-8 with U+FFFD, so a plain string field cannot
// carry an argument built from arbitrary bytes without corrupting it. Cmd gets
// the same treatment Stdin already has (docs/protocol.md §3: "every field
// whose value is raw bytes is base64"), applied per element so the argv
// boundaries stay visible on the wire.
func EncodeCmd(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = base64.StdEncoding.EncodeToString([]byte(a))
	}
	return out
}

func DecodeCmd(cmd []string) ([]string, error) {
	out := make([]string, len(cmd))
	for i, c := range cmd {
		b, err := base64.StdEncoding.DecodeString(c)
		if err != nil {
			return nil, fmt.Errorf("cmd[%d] is not valid base64: %w", i, err)
		}
		out[i] = string(b)
	}
	return out, nil
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

// Sanitize is Sanitizer for the exec channel's response frame. Data is base64
// and is decoded by the caller, which is what SafeBody is for; every other
// field here is a short string the guest chose.
func (r *ExecResponse) Sanitize() {
	r.Stream, r.Signal = SafeText(r.Stream), SafeText(r.Signal)
	r.Error.Sanitize()
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

// Sanitize is Sanitizer for the ready frame. Every field here is a string the
// guest chose, and the boot line is where a person reads which walls are
// around their sandbox — SafeText's own doc comment calls it the sharpest
// case, and until P7-17/F20 the ready frame was the one that reached the
// terminal without it.
func (r *Ready) Sanitize() {
	r.Type, r.BootID, r.Arch = SafeText(r.Type), SafeText(r.BootID), SafeText(r.Arch)
	r.Kernel, r.Supervisor = SafeText(r.Kernel), SafeText(r.Supervisor)
	r.Profile, r.ProfileError = SafeText(r.Profile), SafeText(r.ProfileError)
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

// Sanitize is Sanitizer for a guest event. Every string here is the guest's
// own choice of bytes — a process name, a plugin's name and its crash message
// — and host/run.go both prints them live and appends them to the flight
// recorder, which is why they are cleaned here at the edge rather than at each
// of those (P7-17/F20).
//
// Type is included even though it is only ever compared against the constants
// below: a clean value is returned unchanged, and a hostile one no longer
// matches, which routes it to the "unknown guest event type" branch that
// already refuses to record it.
func (e *GuestEvent) Sanitize() {
	e.Type, e.Comm, e.Name = SafeText(e.Type), SafeText(e.Comm), SafeText(e.Name)
	e.Tool, e.Outcome = SafeText(e.Tool), SafeText(e.Outcome)
	e.Message, e.Args = SafeText(e.Message), SafeText(e.Args)
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

// Sanitize is Sanitizer for the control channel's response. A restored machine
// never sends a ready frame, so this is the only place its profile string
// reaches the host — the same field, and so the same rule.
func (r *ControlResponse) Sanitize() {
	r.Profile, r.ProfileError = SafeText(r.Profile), SafeText(r.ProfileError)
	r.Error.Sanitize()
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
type Reader struct {
	s *bufio.Scanner
	// r is the same reader s scans from, kept so DrainOverlongLine can read
	// past what the scanner gave up on (see there), and so the scanner can be
	// rebuilt in place once it has.
	r   io.Reader
	max int
}

func NewReader(r io.Reader) *Reader { return NewReaderLimit(r, MaxLine) }

// NewReaderLimit is NewReader with a frame limit of the caller's choosing. The
// MCP channels use it with MaxMCPLine; nothing else should need it.
func NewReaderLimit(r io.Reader, max int) *Reader {
	p := &Reader{r: r, max: max}
	p.resetScanner()
	return p
}

// resetScanner (re)builds the scanner p reads through. bufio.Scanner
// "[stops] unrecoverably at EOF, the first I/O error, or a token too large to
// fit in the buffer" (its own doc comment) — ErrTooLong included, whatever
// caused it. A Scan() after that does not simply keep failing the way an
// ordinary sticky error would: on the very next call it hands back the
// already-buffered, oversized data as a final token, as if the stream had
// legitimately ended there, and json.Unmarshal on that garbage is what a
// caller actually observes — not the ErrLineTooLong it might expect to keep
// seeing. DrainOverlongLine calls this once it has found the real frame
// boundary, so the scanner that resumes has none of that stale state and
// reads the connection's next bytes as what they are, not as leftovers of the
// line that just failed.
func (p *Reader) resetScanner() {
	s := bufio.NewScanner(p.r)
	s.Buffer(make([]byte, 0, 64<<10), p.max)
	p.s = s
}

// Read decodes the next frame into v. It returns io.EOF at end of stream,
// ErrLineTooLong if the peer exceeded the frame limit, and *MalformedFrame if
// a complete frame was found but would not decode. Most callers should treat
// either of the latter two as fatal for the connection, same as any other
// error; a caller willing to do more — draining the rest of an oversized line
// with DrainOverlongLine first — can resync and keep the connection instead
// (supervisor/mcp.go does, for the MCP session channel).
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
		if err := json.Unmarshal(line, v); err != nil {
			return &MalformedFrame{Err: err}
		}
		if s, ok := v.(Sanitizer); ok {
			s.Sanitize()
		}
		return nil
	}
}

// Sanitizer is implemented by every frame type whose string fields the far
// side of the channel chose. Read calls it on the decoded value, which is the
// single point where bytes off a socket become Go strings the host will print,
// record and render.
//
// This is where the rule lives because it is the only place that sees every
// one of them. P7-17/F20 counted eight print sites for these fields across
// four commands plus one rec.Append — and the append is the reason a
// per-print fix is not enough: host/run.go recorded a guest-chosen process
// name into the hash chain verbatim, so the escape sequence outlived the run
// and came back on every later replay. Cleaning it here means it is never
// recorded in the first place, and strconv.Quote is reversible, so the record
// loses nothing by carrying the escaped form.
//
// It also reaches readers this package cannot see: internal/sandbox's
// serveEvents and serveReady decode into a GuestEvent and into an anonymous
// struct embedding Ready, and Go promotes the embedded method, so both get
// the sanitiser without either knowing it exists.
//
// A Sanitize implementation must be idempotent — SafeText's output contains no
// character SafeText reacts to — because a value may be read, forwarded and
// read again.
type Sanitizer interface{ Sanitize() }

// maxDrainOverlong bounds how many bytes DrainOverlongLine will read past the
// frame it already refused. It is a small multiple of the reader's own frame
// limit — generous enough to reach the end of a line that merely overshot the
// limit, not so generous that a peer which simply never sends a newline turns
// draining into another way to hold the goroutine open indefinitely; a peer
// like that is answered with ErrLineTooLong and the connection is closed, the
// same as before this existed.
const maxDrainOverlong = 4 * MaxMCPLine

// DrainOverlongLine discards what is left of a line that just failed Read with
// ErrLineTooLong. It reads directly off the underlying connection rather than
// through the scanner, whose own buffer stopped growing at the frame limit and
// holds nothing past that point — every byte still to come is unread on the
// wire (see Read; bufio.Scanner never consumes more than the max it was
// configured with while searching for one token). It stops at the next
// newline, at EOF, at a read error, or after maxDrainOverlong bytes, whichever
// comes first.
//
// Calling this before answering an oversized frame is what keeps that answer
// from racing bytes the peer is still sending on the same line: writing a
// reply — or worse, closing the connection — while the tail of the oversized
// line is still unread can interleave with it or be cut short by a reset, and
// either way risks losing the one reply the caller had left to send. Draining
// first leaves the stream sitting on a clean frame boundary, so the reply goes
// out clean and — if the caller chooses to — serving can simply continue from
// there.
//
// A non-nil return means no newline was found: the connection ended, failed,
// or the peer kept talking past the bound above. That stream is not resynced
// to anything and the caller should treat it as it would any other dead
// connection.
func (p *Reader) DrainOverlongLine() error {
	buf := make([]byte, 32<<10)
	var total int
	for {
		n, err := p.r.Read(buf)
		for _, b := range buf[:n] {
			if b == '\n' {
				// The scanner that hit ErrLineTooLong is not safe to keep
				// using (see resetScanner) — rebuild it now, at the exact
				// point in the stream this drain stopped at, so the next
				// Read starts clean rather than replaying the scanner's own
				// stale, already-buffered state.
				p.resetScanner()
				return nil
			}
		}
		total += n
		if total > maxDrainOverlong {
			return ErrLineTooLong
		}
		if err != nil {
			return err
		}
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
//
// The predicate is unicode.IsPrint and not an ASCII control range, which is
// P7-17/F1: the range missed the whole Cf category. The bidirectional
// overrides and isolates — U+202E, U+2066 to U+2069, the Trojan Source class —
// reorder how a line renders without changing a byte of its logical content,
// in a terminal and in a browser alike, so a guest gets to choose how its own
// audit record reads to a person while the record itself says something else.
// IsPrint also rejects zero-width joiners, soft hyphens, and every space other
// than U+0020, all of which are invisible and all of which make two different
// strings read identically. For an identity-like field — a domain in a blocked
// -egress line, a path, a store key, a command — that is the right side to err
// on. strconv.Quote already renders U+202E as \u202e; it only needed calling.
func SafeText(s string) string {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// SafeBody is SafeText's counterpart for the one field shape SafeText is the
// wrong fit for: a command's captured output, printed to a terminal on replay.
//
// Quoting the whole blob on one stray byte would turn genuinely useful,
// multi-line, coloured output into an unreadable single-line wall of
// backslashes — a larger regression than the property being defended, which is
// the same judgement internal/report's safeBody already made for the HTML page.
// So this keeps what output legitimately contains and removes what it does not:
//
//   - \n and \t survive. A body is multi-line; that is what makes it a body.
//   - SGR — ESC [ … m, the colour and attribute sequences — survives, so a
//     test runner's red FAIL still reads as one.
//   - Everything else becomes U+FFFD: every other C0 byte, DEL, an ESC
//     introducing anything but SGR, any rune unicode.IsPrint rejects, and any
//     byte that is not valid UTF-8.
//
// The exclusions are the point. ESC ] is OSC, which sets the window title and
// mints hyperlinks; ESC [ … J and ESC [ … H erase the screen and move the
// cursor, which is how a guest rewrites lines the host already printed; and a
// bare \r drives the cursor back over the fixed prefix `kelyfos log` puts in
// front of every output line, which is how a guest gets to speak in the host's
// own voice. \r is therefore NOT in the keep list even though \n and \t are —
// the one deliberate difference from internal/report's safeBody, which renders
// into a <pre> where \r moves nothing.
func SafeBody(s string) string {
	if !bodyNeedsSanitising(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if c := s[i]; c < utf8.RuneSelf {
			switch {
			case c == '\n' || c == '\t':
				b.WriteByte(c)
			case c == esc:
				if n := sgrLen(s[i:]); n > 0 {
					b.WriteString(s[i : i+n])
					i += n
					continue
				}
				b.WriteRune(utf8.RuneError)
			case c < 0x20 || c == 0x7f:
				b.WriteRune(utf8.RuneError)
			default:
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Not valid UTF-8. Command output is arbitrary bytes, so this is
			// an ordinary case, not a hostile one; it is replaced rather than
			// passed through because a terminal decoding it is anyone's guess.
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		// P7-17/F1: the same clause SafeText got. Output legitimately
		// contains non-ASCII; it does not legitimately contain direction
		// overrides. The cost is that a no-break space or another
		// non-U+0020 space in genuine output is replaced too — visible,
		// inert, and the same trade this function already makes for a \r.
		if !unicode.IsPrint(r) {
			b.WriteRune(utf8.RuneError)
			i += size
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

const esc = 0x1b

// maxSGRParams bounds how far sgrLen will scan for a terminating 'm'. Real
// colour sequences are a handful of bytes; an ESC [ followed by a megabyte of
// digits is not one, and treating it as SGR would mean copying it through.
const maxSGRParams = 64

// sgrLen returns the length of the SGR sequence at the start of s, or 0 if
// what is there is not one. The shape is ESC [ P* I* F where P is 0x30-0x3f,
// I is 0x20-0x2f and F — the final byte, the one that says what the sequence
// does — must be 'm'.
func sgrLen(s string) int {
	if len(s) < 3 || s[0] != esc || s[1] != '[' {
		return 0
	}
	i := 2
	for i < len(s) && i < 2+maxSGRParams && s[i] >= 0x30 && s[i] <= 0x3f {
		i++
	}
	for i < len(s) && i < 2+maxSGRParams && s[i] >= 0x20 && s[i] <= 0x2f {
		i++
	}
	if i < len(s) && s[i] == 'm' {
		return i + 1
	}
	return 0
}

// bodyNeedsSanitising is the fast path: a body of plain ASCII with no control
// bytes but \n and \t is returned as it came, without allocating. Anything
// else — a control byte, or any non-ASCII at all — takes the walk above, which
// rewrites clean UTF-8 to itself.
func bodyNeedsSanitising(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f || c >= utf8.RuneSelf {
			return true
		}
	}
	return false
}
