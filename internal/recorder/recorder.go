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
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Version is the schema version stamped on every event.
const Version = 1

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

	digest, err := hashOf(e)
	if err != nil {
		return err
	}
	e.Hash = digest

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	// O_APPEND makes the seek-and-write atomic, and the lock above keeps the
	// chain consistent across processes.
	if _, err := r.f.Write(line); err != nil {
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

// Verify walks a flight recorder and reports the first place the chain breaks.
//
// It answers a narrow question honestly: has this file been edited in place
// since it was written? Anyone who can write the file can also rewrite it end
// to end and recompute every digest. What the chain catches is the *selective*
// edit — removing one blocked-egress event, softening one command — which is
// the edit someone covering their tracks actually wants to make.
func Verify(r io.Reader) (events int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
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
			return events, fmt.Errorf("line %d is not a valid event: %w", line, err)
		}
		if e.Seq != line {
			return events, fmt.Errorf("line %d has seq %d — the chain has a gap or was reordered", line, e.Seq)
		}
		if e.Prev != prev {
			return events, fmt.Errorf("event %d does not follow event %d — prev is %q, expected %q",
				e.Seq, e.Seq-1, short(e.Prev), short(prev))
		}
		want, err := hashOf(e)
		if err != nil {
			return events, err
		}
		if want != e.Hash {
			return events, fmt.Errorf("event %d has been modified — its contents hash to %s, but it carries %s",
				e.Seq, short(want), short(e.Hash))
		}
		prev = e.Hash
		events++
	}
	return events, sc.Err()
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
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
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
