// Package recorder implements the KelyfOS flight recorder: an append-only,
// hash-chained JSONL record of everything the host observed during a session.
//
// The schema is documented in docs/events.md and is the stable contract every
// viewer builds on. Events are always written by the host, never by the guest —
// a guest that could write its own audit trail could also write a flattering
// one.
package recorder

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Version is the schema version stamped on every event.
const Version = 1

// MaxLine is the largest line the flight recorder guarantees to write, and the
// size every reader of one bounds its scanner to: Verify and Read below, and
// `kelyfos log`'s replay (host/log.go). One constant rather than the matching
// literal `8<<20` written out three times, because three copies of a number
// that must never drift can drift — Append's own writer guard (see
// fitUnderMaxLine) is what makes the invariant "no writer of this file can
// produce a line its own readers cannot read" hold, and it can only do that
// against a number the readers actually use (S1).
const MaxLine = 8 << 20

// Event types.
const (
	TypeSessionStart    = "session.start"
	TypeSessionReady    = "session.ready"
	TypeSessionEnd      = "session.end"
	TypeCommandStart    = "command.start"
	TypeCommandOutput   = "command.output"
	TypeCommandExit     = "command.exit"
	TypeFileWrite       = "file.write"
	TypeEgressAttempt   = "egress.attempt"
	TypeSecretUse       = "secret.use"
	TypeSecretWithheld  = "secret.withheld"
	TypeSecretScrubbed  = "secret.scrubbed"
	TypeResourceOOM     = "resource.oom"
	TypeResourceTimeout = "resource.timeout"
	TypeResourceSummary = "resource.summary"
	TypeTeamMessage     = "team.message"
	TypeTeamRefused     = "team.refused"
	TypeTeamStore       = "team.store"
	TypeTeamSpawn       = "team.spawn"
	TypeMCPHostCall     = "mcp.host.call"
	TypeMCPHostResult   = "mcp.host.result"
	TypePluginCall      = "plugin.call"
	TypePluginCrash     = "plugin.crash"
	TypeSessionPause    = "session.pause"
	TypeSessionResume   = "session.resume"
	TypeRunReview       = "run.review"
	TypeShellStart      = "shell.start"
	TypeShellEnd        = "shell.end"
	TypeForwardAccept   = "forward.accept"
	// TypeSessionPolicy is P7-2's addition: what a machine was permitted to
	// do, declared once per machine at the door that made it, alongside that
	// machine's session.ready — never on session.start, for the reason
	// docs/policy-record.md §3 gives (a team's session.start opens one chain
	// for several machines, and session.policy describes one).
	TypeSessionPolicy = "session.policy"
)

// ReasonServeMCP marks a session.start as a server's own session rather than a
// machine's: its lanes are the sandboxes it made, the way a team session's
// lanes are its agents. Both the host that writes it and the report that reads
// it take the string from here, so the two cannot drift (E4-4).
const ReasonServeMCP = "serve-mcp"

// Sources.
const (
	SourceHost  = "host"
	SourceGuest = "guest"
)

// Event is one line of the flight recorder.
//
// Field order here is the canonical order the hash is computed over, so
// reordering this struct changes every digest — which is why the order is
// pinned in docs/events.md §3 rather than left to taste.
type Event struct {
	V       int    `json:"v"`
	Seq     int    `json:"seq"`
	TS      string `json:"ts"`
	Sandbox string `json:"sandbox"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	Prev    string `json:"prev"`
	Hash    string `json:"hash"`

	// session.start
	Image   string   `json:"image,omitempty"`
	Arch    string   `json:"arch,omitempty"`
	Kelyfos string   `json:"kelyfos,omitempty"`
	Argv    []string `json:"argv,omitempty"`

	// session.ready
	BootMS     int64  `json:"boot_ms,omitempty"`
	Kernel     string `json:"kernel,omitempty"`
	Supervisor string `json:"supervisor,omitempty"`
	Overlay    *bool  `json:"overlay,omitempty"`

	// session.end
	Reason     string `json:"reason,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`

	// command.*
	Call   string   `json:"call,omitempty"`
	Cmd    []string `json:"cmd,omitempty"`
	Cwd    string   `json:"cwd,omitempty"`
	Via    string   `json:"via,omitempty"`
	Stream string   `json:"stream,omitempty"`
	Data   string   `json:"data,omitempty"`
	Bytes  int      `json:"bytes,omitempty"`
	Code   *int     `json:"code,omitempty"`
	Signal string   `json:"signal,omitempty"`
	Error  *EvError `json:"error,omitempty"`

	// file.write
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`

	// egress.attempt
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Allowed  *bool  `json:"allowed,omitempty"`
	Mode     string `json:"mode,omitempty"`
	BytesIn  int64  `json:"bytes_in,omitempty"`
	BytesOut int64  `json:"bytes_out,omitempty"`

	// secret.use
	Name string `json:"name,omitempty"`

	// resource.oom. Appended at the end of the struct on purpose: the field
	// order here is the canonical order the hash is computed over, so adding a
	// field anywhere else would change the digest of every event that has one.
	PID    int    `json:"pid,omitempty"`
	Comm   string `json:"comm,omitempty"`
	RSSKiB int64  `json:"rss_kib,omitempty"`
	MemMiB int    `json:"mem_mib,omitempty"`

	// resource.timeout
	Budget    string `json:"budget,omitempty"`
	BudgetMS  int64  `json:"budget_ms,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms,omitempty"`

	// team.message and team.refused (E2-1). From and To are agent names inside
	// one team; Kind is send, ask or reply; Outcome is what happened to it.
	// Data carries the payload only when the team asked for capture, and
	// SHA256 is present either way — a digest lets a later claim about a
	// message be checked without the log holding a second copy of it.
	Agent   string `json:"agent,omitempty"`
	Peer    string `json:"peer,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Outcome string `json:"outcome,omitempty"`

	// resource.summary — the usage receipt, written once at teardown.
	CPUSeconds     float64 `json:"cpu_seconds,omitempty"`
	PeakRSSKiB     int64   `json:"peak_rss_kib,omitempty"`
	NetInBytes     int64   `json:"net_in_bytes,omitempty"`
	NetOutBytes    int64   `json:"net_out_bytes,omitempty"`
	DiskReadBytes  int64   `json:"disk_read_bytes,omitempty"`
	DiskWriteBytes int64   `json:"disk_write_bytes,omitempty"`
	VcpuCount      int     `json:"vcpu_count,omitempty"`
	CPUQuota       int     `json:"cpu_quota_percent,omitempty"`
	// BlockedPackets is the sandbox's own nftables drop counter
	// (internal/sandbox/network.go's BlockedPackets), zero for a sandbox with
	// no network at all rather than absent — the same "no interface, not
	// merely no traffic" distinction the egress lines elsewhere in this
	// product already draw (F14).
	BlockedPackets int64 `json:"blocked_packets,omitempty"`

	// mcp.host.* (E4-4). Args is a redacted summary of a client tool call's
	// arguments — every key it was given, with anything carrying content
	// replaced by its size, because the rule for what a record may hold is the
	// same here as it is for file.write. Appended at the end for the reason the
	// resource.oom block gives: this order is the order the hash is computed
	// over.
	Args string `json:"args,omitempty"`

	// plugin.call and plugin.crash (E4-7). Name carries the plugin, as every
	// other event that names a thing does; Tool is the plugin's own name for
	// what was called, without the prefix, because the prefix is already in
	// Name and repeating it would make the two disagree eventually.
	Tool string `json:"tool,omitempty"`

	// run.review (E5-2). The counts a person was shown before they decided,
	// so the record holds what the decision was about and not only what it was.
	Added    int `json:"added,omitempty"`
	Modified int `json:"modified,omitempty"`
	Deleted  int `json:"deleted,omitempty"`

	// session.ready (P5-1, placed by D32). Whether the VMM ran inside the
	// jailer: a chroot,
	// a dropped uid, its own device nodes. In the record because a chain that
	// does not say which wall was around a run is a chain that overstates the
	// weaker one — the same rule that made `mode` on an egress attempt say how
	// much of the connection the proxy could actually read.
	Jailed *bool `json:"jailed,omitempty"`

	// forward.accept (E5-5). Port is the host port the connection arrived on
	// and GuestPort is where it was carried to; Peer is who connected. A
	// connection is the unit somebody would ask about, so this is written per
	// connection and never per packet or per byte.
	GuestPort int `json:"guest_port,omitempty"`

	// session.ready (P5-3, P5-7). What the guest's own
	// supervisor confined every process it spawned with — the flavor's profile,
	// the writable trees, how many syscalls it refused. Empty means no
	// confinement, which is what a machine restored from a pre-v0.9 snapshot
	// has: restoring a snapshot does not upgrade the guest inside it, and a
	// chain that said nothing here would let such a run read as a confined one
	// (D32). Appended at the end, like Jailed before it, because the field order
	// in this struct is the order the hash is computed over.
	Profile string `json:"profile,omitempty"`

	// session.policy (P7-2, docs/policy-record.md §5). What the machine was
	// permitted. Three of the eleven [resources] caps already exist above —
	// VcpuCount, MemMiB and CPUQuota — and are reused rather than duplicated;
	// the remaining eight caps and everything else session.policy carries are
	// new, appended here in the order docs/policy-record.md §5 fixes as
	// normative (positions 1-19). Never a secret value: EvSecret carries a
	// name, a host and a path scope, and nothing else.
	DiskBytes     int64      `json:"disk_bytes,omitempty"`
	ScratchBytes  int64      `json:"scratch_bytes,omitempty"`
	NetMbpsRx     int        `json:"net_mbps_rx,omitempty"`
	NetMbpsTx     int        `json:"net_mbps_tx,omitempty"`
	DiskIOPS      int        `json:"disk_iops,omitempty"`
	DiskMbps      int        `json:"disk_mbps,omitempty"`
	MaxRuntimeMS  int64      `json:"max_runtime_ms,omitempty"`
	IdleTimeoutMS int64      `json:"idle_timeout_ms,omitempty"`
	Allow         []string   `json:"allow,omitempty"`
	Ports         []int      `json:"ports,omitempty"`
	Secrets       []EvSecret `json:"secrets,omitempty"`
	Workspace     string     `json:"workspace,omitempty"`
	Plugins       []string   `json:"plugins,omitempty"`
	Forwards      []string   `json:"forwards,omitempty"`
	RootfsSHA256  string     `json:"rootfs_sha256,omitempty"`
	KernelSHA256  string     `json:"kernel_sha256,omitempty"`
	Tools         []string   `json:"tools,omitempty"`
	ParentSession string     `json:"parent_session,omitempty"`
	Traceparent   string     `json:"traceparent,omitempty"`
}

// WithPosture fills the two fields that say which walls were around a machine.
//
// One call rather than two assignments, because the failure this guards against
// has already happened once: P5-1 added Jailed and set it at one of the eight
// places that open a chain, so seven kinds of session said nothing about a wall
// that was in fact around them. A pair that is always written together is
// harder to write half of.
func (e Event) WithPosture(jailed bool, profile string) Event {
	e.Jailed = &jailed
	e.Profile = profile
	return e
}

type EvError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

// EvSecret is one bound credential on a session.policy — never its value.
// Name and Host mirror what secret.use already writes for the same
// credential; Path is the one field with no existing precedent, and comes
// from egress.Secret.Scope.Path (docs/policy-record.md §8.1).
type EvSecret struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Path string `json:"path,omitempty"`
}

// PolicyFields is everything session.policy declares about one machine,
// assembled by the door and handed whole to NewSessionPolicy. A struct
// rather than nineteen positional parameters, because a caller assembling
// nineteen values by position is a caller one reordering away from silently
// swapping two of them — the same reasoning WithPosture's single call
// gives for its own two.
type PolicyFields struct {
	VcpuCount, MemMiB, CPUQuota              int
	DiskBytes, ScratchBytes                  int64
	NetMbpsRx, NetMbpsTx, DiskIOPS, DiskMbps int
	MaxRuntimeMS, IdleTimeoutMS              int64
	Allow, Plugins, Forwards, Tools          []string
	Ports                                    []int
	Secrets                                  []EvSecret
	Workspace, RootfsSHA256, KernelSHA256    string
	ParentSession, Traceparent               string
}

// NewSessionPolicy is session.policy's one constructor (docs/policy-record.md
// §5, §9.3's door-enumerating test). Every door that opens a machine builds a
// PolicyFields and calls this rather than filling in an Event literal by
// hand, so a field present at one door and forgotten at another cannot
// happen — the same failure WithPosture already exists to close for jailed
// and profile, applied here to the wider set session.policy carries.
//
// agent is the team member's name inside a team, or "" outside one — the
// same convention session.ready already uses, so a reader who has learned
// that convention once does not have to learn it twice.
func NewSessionPolicy(agent string, p PolicyFields) Event {
	return Event{
		Type:  TypeSessionPolicy,
		Agent: agent,

		VcpuCount: p.VcpuCount,
		MemMiB:    p.MemMiB,
		CPUQuota:  p.CPUQuota,

		DiskBytes:     p.DiskBytes,
		ScratchBytes:  p.ScratchBytes,
		NetMbpsRx:     p.NetMbpsRx,
		NetMbpsTx:     p.NetMbpsTx,
		DiskIOPS:      p.DiskIOPS,
		DiskMbps:      p.DiskMbps,
		MaxRuntimeMS:  p.MaxRuntimeMS,
		IdleTimeoutMS: p.IdleTimeoutMS,
		Allow:         p.Allow,
		Ports:         p.Ports,
		Secrets:       p.Secrets,
		Workspace:     p.Workspace,
		Plugins:       p.Plugins,
		Forwards:      p.Forwards,
		RootfsSHA256:  p.RootfsSHA256,
		KernelSHA256:  p.KernelSHA256,
		Tools:         p.Tools,
		ParentSession: p.ParentSession,
		Traceparent:   p.Traceparent,
	}
}

// Recorder appends events to one session's file.
//
// A session is written by several processes at once — `kelyfos run` holds the
// sandbox open while `kelyfos exec` and `kelyfos mcp` are separate invocations —
// so every append takes an exclusive lock on the file and re-reads whatever
// other writers added since this one last looked. Without that, each process
// keeps its own idea of the sequence number and previous hash, they interleave,
// and the result is a log that can never verify: strictly worse than no log,
// because it looks like one.
type Recorder struct {
	mu      sync.Mutex
	f       *os.File
	seq     int
	prev    string
	off     int64 // how much of the file this process has accounted for
	sandbox string
	started time.Time
}

// SessionsDir is where session records live — deliberately outside the run
// directory, which is deleted when the sandbox stops. The record of what
// happened must outlive the thing it describes.
func SessionsDir(root string) string { return filepath.Join(root, "sessions") }

// Path is the flight recorder file for one sandbox.
func Path(root, sandboxID string) string {
	return filepath.Join(SessionsDir(root), sandboxID, "events.jsonl")
}

// Open creates or reopens a session's recorder.
func Open(root, sandboxID string) (*Recorder, error) {
	path := Path(root, sandboxID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create session directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open flight recorder: %w", err)
	}
	return &Recorder{f: f, sandbox: sandboxID, started: time.Now()}, nil
}

// catchUp reads everything appended since this process last looked, so seq and
// prev reflect the true end of the chain. The caller holds the file lock.
func (r *Recorder) catchUp() error {
	info, err := r.f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == r.off {
		return nil
	}
	buf := make([]byte, info.Size()-r.off)
	if _, err := r.f.ReadAt(buf, r.off); err != nil && err != io.EOF {
		return err
	}
	for _, line := range bytes.Split(buf, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("flight recorder is corrupt after byte %d: %w", r.off, err)
		}
		r.seq, r.prev = e.Seq, e.Hash
	}
	r.off = info.Size()
	return nil
}

// Append stamps, chains and writes one event. The caller fills in Type and the
// type-specific fields; everything in the common header is set here so it
// cannot be got wrong at a call site.
//
// Events are flushed on every write. Buffering an audit log costs nothing to
// lose in the happy path and loses exactly the interesting events when a
// process dies unexpectedly.
func (r *Recorder) Append(e Event) error {
	if r == nil {
		return nil // recording disabled
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := unix.Flock(int(r.f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock flight recorder: %w", err)
	}
	defer unix.Flock(int(r.f.Fd()), unix.LOCK_UN)

	if err := r.catchUp(); err != nil {
		return err
	}

	r.seq++
	e.V = Version
	e.Seq = r.seq
	e.TS = time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	e.Sandbox = r.sandbox
	if e.Source == "" {
		e.Source = SourceHost
	}
	e.Prev = r.prev
	e.Hash = ""

	// Every reader of this file — Verify, Read, and host/log.go's replay — caps
	// its scanner at MaxLine. Nothing upstream of Append enforces that on a
	// caller's behalf: internal/egress's splitTarget used to let an oversized
	// CONNECT host reach an egress.attempt's Host field, and
	// host/mcpobserve.go's exec-output path used to hand a whole, unchunked
	// command's stdout to Data. Both doors are closed now, but this guard is
	// unconditional on purpose — the invariant is "no writer of this file can
	// produce a line its own readers cannot read," not "no *known* writer" (S1).
	//
	// This has to run before hashOf: hashOf hashes exactly the struct Append is
	// about to marshal and write, so a field clipped afterwards would make the
	// written line disagree with its own digest, and Verify would report every
	// clipped event as "modified."
	//
	// r.seq is rolled back on every error return from here on: it was bumped
	// above so e.Seq could be stamped before it is known whether this line will
	// actually be written, and a refused event must free its sequence number
	// back up rather than leave a permanent gap for the *next* Append to land
	// on — Verify treats a gap as "the chain has a gap or was reordered" and
	// that would break every event after it, for a session that otherwise wrote
	// nothing wrong.
	if err := fitUnderMaxLine(&e); err != nil {
		r.seq--
		return err
	}

	digest, err := hashOf(e)
	if err != nil {
		r.seq--
		return err
	}
	e.Hash = digest

	line, err := json.Marshal(e)
	if err != nil {
		r.seq--
		return err
	}
	line = append(line, '\n')
	// O_APPEND makes the seek-and-write atomic, and the lock above keeps the
	// chain consistent across processes.
	if _, err := r.f.Write(line); err != nil {
		r.seq--
		return err
	}
	r.prev = digest
	r.off += int64(len(line))
	return nil
}

func (r *Recorder) Since() time.Duration { return time.Since(r.started) }

// Session is the id this recorder writes under. Handed to a team's sandboxes so
// their own tooling records into the same chain (E2-7).
func (r *Recorder) Session() string {
	if r == nil {
		return ""
	}
	return r.sandbox
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// hashOf computes an event's digest over its canonical form: the event with
// Hash emptied, serialized in the struct's declared field order.
func hashOf(e Event) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// clipMargin is slack kept below MaxLine on top of the 64 bytes a real digest
// adds once hashOf fills Hash in (see fitUnderMaxLine). It covers the
// "...(clipped from N to M bytes)" note clipLargestField appends and the
// escaping growth a clipped field can pick up when it is re-marshalled — both
// small, but the loop re-measures after every clip precisely so a fixed margin
// never has to be exact, only generous enough to converge quickly.
const clipMargin = 4 << 10

// maxClipAttempts bounds fitUnderMaxLine's loop. Halving the single largest
// candidate field converges in one or two iterations for anything this
// product's own doors could produce — a 16 MiB MCP frame's stdout, base64
// expanded, is under 22 MiB, and two halvings already clear MaxLine — so the
// bound exists only so a field this code does not yet know about cannot turn
// "clip until it fits" into "loop forever." Exceeding it fails the Append
// closed rather than write a line no reader could get past.
const maxClipAttempts = 8

// fitUnderMaxLine is Append's own backstop: whatever door let an oversized,
// guest-influenced field reach here, the line Append is about to write must
// still be one every reader — Verify, Read, `kelyfos log`'s replay — can read
// back whole. It must run before hashOf; see the comment at its call site.
func fitUnderMaxLine(e *Event) error {
	for attempt := 0; ; attempt++ {
		b, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("measuring event %d before recording it: %w", e.Seq, err)
		}
		// e.Hash is "" here — the state Append is always in when this runs —
		// and grows to a 64-character hex digest once hashOf fills it in, which
		// is the only change left between this measurement and the line Append
		// actually writes.
		if len(b)+sha256.Size*2+clipMargin <= MaxLine {
			return nil
		}
		if attempt >= maxClipAttempts {
			return fmt.Errorf("event %d (%s) is still %d bytes after %d clips — refusing to write a line no reader could read back",
				e.Seq, e.Type, len(b), attempt)
		}
		if !clipLargestField(e) {
			return fmt.Errorf("event %d (%s) is %d bytes with nothing left to clip",
				e.Seq, e.Type, len(b))
		}
	}
}

// clipLargestField halves whichever of the event's fields is currently
// largest, noting the original size in-band rather than adding a schema field
// — the same pattern host/servemcpaudit.go's summariseArgs uses for the
// outward MCP audit lane, reused here as the last line of defense for the
// flight recorder itself. It reports false when nothing is left worth
// clipping, which fitUnderMaxLine treats as "cannot make this fit."
//
// The candidate string fields come from largestStringField, which walks the
// struct by reflection rather than a hand-maintained list — a hand-maintained
// list is exactly what F8 found wrong with the previous version of this
// function: it named six fields (Data, Args, Host, Path, Name, and Cmd) while
// claiming to cover "whatever field made it that large," and EvError.Message,
// Reason, Tool and every other string field on Event were invisible to it. An
// oversized value in one of those went through fitUnderMaxLine's loop with
// nothing to clip, so Append failed closed and the event vanished from the
// record instead of being clipped and kept — the exact failure mode this
// function exists to prevent. Reflection means a field added to Event next
// month is covered the day it lands, not the day someone reads this function
// and remembers to add it to a list.
//
// Cmd is measured and clipped separately because it is a []string, not a
// string, so reflection over string-kinded fields does not see it: an
// external review of this fix found that a caller-supplied argv
// (host/mcpobserve.go, host/servemcptools.go, host/exec.go all build Cmd from
// a request field with no upstream length bound) could be the single largest
// thing on a command.start event while every string field was empty. Cmd
// competes for "largest field" like everything else, and clips to a single
// summarising element rather than being left unclippable.
//
// P7-2 added six more slices reflection cannot see the same way: Allow,
// Secrets, Plugins, Forwards and Tools are all string-shaped like Cmd (Secrets
// is []EvSecret rather than []string, but is still invisible to
// largestStringField's field-kind switch), and Ports is not, so it gets its
// own measurement and its own clip (below). Argv is included too, even though
// it is bounded in practice by the OS's own argv length limit and has never
// been observed oversized: docs/policy-record.md §9.1 already draws the same
// conclusion about Ports ("bounded and small in practice... but it is still,
// mechanically, a slice reflection does not see, and a fixture should say so
// explicitly rather than leave it untested by omission"), and the same
// argument applies here.
//
// Tools was the one P7-2 actually missed — the review that reopened P7-2
// (F1) found it: the six-item list above named five of P7-2's six new
// slices and Tools slipped through anyway, the identical shape of mistake
// F8 made for strings one paragraph up, just one level down the type
// system. A hand-maintained list has now failed exactly this way twice, so
// TestClipLargestFieldCoversEverySliceField (fuzz_test.go) backstops this
// list itself: it walks Event by reflection for every slice-kind field —
// present or future — and fails if this function does not have a case for
// it, rather than depending on a fifth person remembering to add one.
// Extending this list is still required in the same commit that adds a new
// slice field to Event; that test is what makes forgetting loud instead of
// silent.
func clipLargestField(e *Event) bool {
	target := largestStringField(e)
	best := 0
	if target != nil {
		best = len(*target)
	}

	type slice struct {
		n     int // element count — the guard below keys on this, not bytes
		bytes int
		clip  func()
	}
	slices := []slice{
		{len(e.Argv), stringsBytes(e.Argv), func() { e.Argv = clipStrings(e.Argv, "process arguments") }},
		{len(e.Cmd), stringsBytes(e.Cmd), func() { e.Cmd = clipStrings(e.Cmd, "argv elements") }},
		{len(e.Allow), stringsBytes(e.Allow), func() { e.Allow = clipStrings(e.Allow, "domains") }},
		{len(e.Plugins), stringsBytes(e.Plugins), func() { e.Plugins = clipStrings(e.Plugins, "plugin names") }},
		{len(e.Forwards), stringsBytes(e.Forwards), func() { e.Forwards = clipStrings(e.Forwards, "forwards") }},
		{len(e.Tools), stringsBytes(e.Tools), func() { e.Tools = clipStrings(e.Tools, "tool names") }},
		{len(e.Secrets), secretsBytes(e.Secrets), func() { e.Secrets = clipSecrets(e.Secrets) }},
		{len(e.Ports), portsBytes(e.Ports), func() { e.Ports = clipPorts(e.Ports) }},
	}
	// Guarding on element count rather than "bytes > 0" (F6): stringsBytes and
	// secretsBytes measure element content only, not the per-element JSON
	// framing every entry still costs once marshalled (quotes, colons, the
	// comma between entries) — a slice of many empty or zero-value elements
	// used to measure near-zero bytes and lose to any nonempty string field,
	// even though the real marshalled line from that many empty elements
	// could itself be the reason the line is oversized. bytes now includes a
	// per-element estimate of that framing (below) so the comparison against
	// best is realistic, and the guard is len > 0 rather than bytes > 0 so a
	// slice is never skipped purely because its own measurement undercounts.
	var chosen *slice
	for i := range slices {
		if slices[i].n > 0 && slices[i].bytes > best {
			best = slices[i].bytes
			chosen = &slices[i]
		}
	}
	if chosen != nil {
		chosen.clip()
		return true
	}

	if target == nil || len(*target) == 0 {
		return false
	}
	orig := len(*target)
	kept := clipUTF8(*target, orig/2)
	*target = fmt.Sprintf("%s...(clipped from %d to %d bytes)", kept, orig, len(kept))
	return true
}

// clipStrings is Cmd's original clip, generalised to any []string field
// P7-2 added: join, keep half the joined bytes, replace the whole slice with
// one element noting what was lost. label names the elements in that note —
// "argv elements" for Cmd reproduces the message exactly as it read before
// this generalisation.
func clipStrings(s []string, label string) []string {
	orig := len(s)
	origBytes := stringsBytes(s)
	joined := strings.Join(s, " ")
	kept := clipUTF8(joined, origBytes/2)
	return []string{fmt.Sprintf("%s...(clipped from %d bytes across %d %s)", kept, origBytes, orig, label)}
}

// secretsBytes is Secrets' size for the same comparison cmdBytes always gave
// Cmd: every field of every entry, since that is what actually reaches the
// wire once marshalled. secretsPerElementOverhead accounts for the JSON
// object framing (F6) — `{"name":"","host":""},` alone is 22 bytes before
// any content — so a slice of many near-empty EvSecret entries is not
// measured as if it costs nothing: 500,000 zero-value entries proved to
// marshal to an 11 MB line while this function, unpadded, measured under a
// kilobyte.
const secretsPerElementOverhead = 22

func secretsBytes(s []EvSecret) int {
	n := 0
	for _, sec := range s {
		n += len(sec.Name) + len(sec.Host) + len(sec.Path) + secretsPerElementOverhead
	}
	return n
}

// clipSecrets replaces an oversized Secrets slice with one placeholder entry
// noting how many were dropped and how large they were. A secret's own
// fields are never guest-influenced — they come from the operator's
// --secret flags or kelyfos.toml, never from a request a guest or an MCP
// client made — but the slice can still grow long enough on a machine that
// declares many, and reflection cannot see it either way (§9.1 of
// docs/policy-record.md).
func clipSecrets(s []EvSecret) []EvSecret {
	return []EvSecret{{Name: fmt.Sprintf("...(clipped from %d bytes across %d secrets)", secretsBytes(s), len(s))}}
}

// portsBytes estimates what Ports contributes to the marshalled line: four
// bytes per entry is enough to decide correctly which field is largest
// without an actual marshal, since a real port number is at most five digits
// plus a comma.
func portsBytes(p []int) int { return len(p) * 4 }

// clipPorts is Ports' clip. There is no string to shrink and annotate the
// way every other field here gets, so an oversized list is truncated to its
// first sixteen entries instead — a ports list that large is already
// meaningless to a reader, and truncating is enough to bound the line.
func clipPorts(p []int) []int {
	const keep = 16
	if len(p) <= keep {
		return p
	}
	return p[:keep]
}

// largestStringField walks every string-typed field reachable from an Event —
// its own top-level fields, plus the fields of any pointed-to struct such as
// *EvError — and returns the address of whichever currently holds the most
// bytes, or nil when every string field is empty. Using the address, rather
// than returning a copy, is what lets clipLargestField overwrite the field it
// found in place.
//
// Walking by reflection instead of a fixed field list is the fix for F8: a
// list has to be remembered and kept in sync by hand, and this file's own
// history is the proof that does not happen reliably. A field this function
// does not yet know how to reach (a nested struct two levels down, say) would
// still miss coverage, but that is a shape Event does not currently have, and
// FuzzAppendFieldValues exercises this by setting every reachable string field
// at once so a future field that *is* reachable and gets missed here fails a
// fuzz run rather than needing a code read to find.
func largestStringField(e *Event) *string {
	var target *string
	consider := func(f *string) {
		if target == nil || len(*f) > len(*target) {
			target = f
		}
	}
	v := reflect.ValueOf(e).Elem()
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.String:
			consider(fv.Addr().Interface().(*string))
		case reflect.Ptr:
			if fv.IsNil() || fv.Type().Elem().Kind() != reflect.Struct {
				continue
			}
			sv := fv.Elem()
			for j := 0; j < sv.NumField(); j++ {
				if sfv := sv.Field(j); sfv.Kind() == reflect.String {
					consider(sfv.Addr().Interface().(*string))
				}
			}
		}
	}
	return target
}

// stringsPerElementOverhead accounts for a []string element's own JSON
// framing — two quotes and a separating comma — so a slice of many empty or
// near-empty strings is not measured as if it costs nothing (F6): 3,000,000
// empty Allow entries proved to marshal to a 9 MB line while this function,
// unpadded, measured zero bytes.
const stringsPerElementOverhead = 3

// stringsBytes is the size clipLargestField and fitUnderMaxLine's marshalled
// measurement both care about for any []string field: the bytes its elements
// actually contribute, not len(s), which is the element count. Named cmdBytes
// until P7-2 needed the same measurement for Allow, Plugins and Forwards too.
func stringsBytes(s []string) int {
	n := 0
	for _, v := range s {
		n += len(v) + stringsPerElementOverhead
	}
	return n
}

// clipUTF8 cuts s to at most n bytes without leaving half a rune at the end —
// the same rule, for the same reason, as host/servemcpaudit.go's clipUTF8: a
// trailing fragment of a multi-byte character would be replaced with U+FFFD by
// json.Marshal, which is not the byte sequence hashOf would then be hashing
// against what a reader sees.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 {
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// Verify walks a flight recorder and reports the first place the chain breaks.
//
// It answers a narrow question honestly: has this file been edited in place
// since it was written? Anyone who can write the file can also rewrite it end
// to end and recompute every digest. What the chain catches is the *selective*
// edit — removing one blocked-egress event, softening one command — which is
// the edit someone covering their tracks actually wants to make.
//
// The head is the digest of the last event, and it is returned by the walk
// rather than read off the last line afterwards. The two would be the same
// value on an intact chain and could differ on a broken one — a head taken from
// a line nobody verified is a number a reader would quote. Returning it here
// makes "how many events, and what did the chain end on" one answer about one
// file, which is what a reader comparing two reports needs it to be.
func Verify(r io.Reader) (events int, head string, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	prev := ""
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return events, "", fmt.Errorf("line %d is not a valid event: %w", line, err)
		}
		if e.Seq != line {
			return events, "", fmt.Errorf("line %d has seq %d — the chain has a gap or was reordered", line, e.Seq)
		}
		if e.Prev != prev {
			return events, "", fmt.Errorf("event %d does not follow event %d — prev is %q, expected %q",
				e.Seq, e.Seq-1, short(e.Prev), short(prev))
		}
		// A line with no digest is not an event this product wrote: Append
		// always fills Hash, and `hash` carries no omitempty, so every recorded
		// line has 64 hex characters there. Without this, the cheapest possible
		// forgery passes — a hand-written chain with `"hash":""` on every line
		// verifies, because the digest of a line with an empty hash is defined
		// as empty and an empty digest matches an empty hash. Found by an
		// adversarial review of P6-6's design, and it mattered from the moment
		// the file being checked stopped being one this machine wrote.
		if e.Hash == "" {
			return events, "", fmt.Errorf("event %d carries no digest — nothing here was written by a flight recorder", e.Seq)
		}
		want := digestOfLine(raw, e.Hash)
		if want != e.Hash {
			return events, "", fmt.Errorf("event %d has been modified — its contents hash to %s, but it carries %s",
				e.Seq, short(want), short(e.Hash))
		}
		prev = e.Hash
		events++
	}
	if err := sc.Err(); err != nil {
		return events, "", err
	}
	return events, prev, nil
}

// digestOfLine recomputes an event's digest from the bytes as written, rather
// than by re-marshalling the parsed struct.
//
// The two agree for every chain ever written — the preimage the writer hashes
// is its struct with Hash blanked, and `hash` carries no omitempty, so that is
// byte-for-byte this line with the digest emptied in place. What differs is
// what happens to a field the reader does not know about. Re-marshalling a
// parsed struct silently drops it and the digest no longer matches, so an older
// build reading a newer chain reports "event N has been modified" — tamper
// detection firing on a legitimate record, which is the loudest false alarm
// this product can produce. Working from the raw bytes preserves whatever is
// there.
//
// That is what makes docs/events.md's "adding a field is not breaking" true.
// It was not, and P6-4 measured it before this was written (D44).
//
// A line whose digest appears twice, or not where the key is, simply fails —
// the substitution is anchored on the key, and anything else is a line nobody
// wrote. The caller has already refused an empty digest, which would otherwise
// make the substitution an identity and the comparison vacuous.
func digestOfLine(raw []byte, hash string) string {
	pre := bytes.Replace(raw, []byte(`"hash":"`+hash+`"`), []byte(`"hash":""`), 1)
	sum := sha256.Sum256(pre)
	return hex.EncodeToString(sum[:])
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	if h == "" {
		return "(none)"
	}
	return h
}

// Read parses a whole flight recorder without verifying it.
func Read(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	var out []Event
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return out, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
