// Package sandbox is the host side of a KelyfOS microVM: where its files live,
// how Firecracker is configured and launched, how the host-side channels are
// bound, and how it is torn down.
package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/denial"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/team"
)

// Root is where KelyfOS keeps everything it generates. It matches the Makefile,
// so a `make image` and a `kelyfos run` agree on where the artifacts are without
// either being told.
func Root() string {
	if v := os.Getenv("KELYFOS_CACHE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp/kelyfos"
	}
	return filepath.Join(home, ".cache", "kelyfos")
}

func ImageDir(arch string) string { return filepath.Join(Root(), "out", arch) }
func RunRoot() string             { return filepath.Join(Root(), "run") }

// Options configure one sandbox.
type Options struct {
	// ID, when set, is used instead of minting a new one — the network has to
	// exist before the sandbox that uses it, and both must agree on the name.
	ID        string
	Arch      string
	Flavor    string
	ImageDir  string
	VcpuCount int
	MemMiB    int
	Quiet     bool
	// Plugins is the read-only device carrying the MCP servers that run inside
	// the guest, or nil when the project declares none (E4-6).
	Plugins *Plugins
	// Allow is the egress allowlist. Empty means the sandbox gets no network
	// interface at all — not a firewalled one, not an empty allowlist, none.
	Allow []string
	// Console, when set, receives the guest's serial output line by line.
	Console io.Writer
	// ProxyPort is the port the egress proxy has already bound on the host TAP
	// address. Set by the caller between NewNetwork and New.
	ProxyPort int
	// Net is the egress plumbing, when there is any.
	Net *Network
	// Workspace is a host directory packed as a second disk, when there is one.
	Workspace *Workspace
	// CPUSlice caps the host CPU time the VMM may consume. Distinct from
	// VcpuCount, which caps parallelism (E1-2).
	CPUSlice *Slice
	// IO caps network and block throughput, enforced by Firecracker's own
	// token-bucket limiters (E1-3). The zero value leaves every device
	// unthrottled.
	IO IOLimits
	// ScratchBytes caps the tmpfs behind the overlay — everything the guest
	// writes outside /work (E1-5). Zero leaves the guest kernel's own default,
	// which is half the guest's RAM.
	ScratchBytes int64
	// Agent is this sandbox's name within a team, or empty for a sandbox that
	// is not in one. It reaches the guest on the kernel command line, so a
	// guest cannot rename itself into another agent's edges (E2-2).
	Agent string
	// Session is the flight recorder events about this sandbox belong in.
	// Empty means its own id, which is what a single run wants. A team member
	// carries the team's session here, so `kelyfos exec` against one agent
	// writes into the same chain as the messages that asked for the work —
	// one transcript rather than five to correlate afterwards (E2-7).
	Session string

	// MaySpawn says this agent's policy granted it a spawn budget. The guest
	// is told, so the spawn tool is listed only where it can work (E2-5).
	MaySpawn bool
	// OnTeamRequest answers the guest's team channel. Nil means the sandbox is
	// not in a team and the channel is not bound at all — a guest that dials it
	// finds nothing, which is the truthful answer.
	OnTeamRequest func(proto.TeamRequest) proto.TeamResponse
	// ReadyTimeout bounds how long a restore waits for the machine to answer.
	// Zero keeps the default. It exists because `team up --ready-timeout` is a
	// promise about every agent, and four of five of them may be forks (E2-9).
	ReadyTimeout time.Duration
	// NoJail runs the VMM outside the jailer (P5-1, docs/hardening.md §2).
	// The default is jailed; this exists for a machine that cannot give the
	// jailer passwordless sudo, it is never a default, and the caller says so
	// on every run that uses it.
	NoJail bool
	// OnGuestEvent receives what the guest reports on the events channel
	// (docs/protocol.md §5.5). The caller decides what to record; the guest
	// never writes the flight recorder itself (docs/events.md §1).
	OnGuestEvent func(proto.GuestEvent)
}

// State is the on-disk description of a running sandbox, written into the run
// directory so a second process — `kelyfos exec` — can find the channels
// without being told where they are.
type State struct {
	ID          string `json:"id"`
	PID         int    `json:"pid"`
	Arch        string `json:"arch"`
	Flavor      string `json:"flavor"`
	UDSPath     string `json:"uds_path"`
	APIPath     string `json:"api_path"`
	TAP         string `json:"tap,omitempty"`
	HostIP      string `json:"host_ip,omitempty"`
	GuestIP     string `json:"guest_ip,omitempty"`
	Netmask     string `json:"netmask,omitempty"`
	HostMAC     string `json:"host_mac,omitempty"`
	ProxyPort   int    `json:"proxy_port,omitempty"`
	Agent       string `json:"agent,omitempty"`
	Session     string `json:"session,omitempty"`
	VcpuCount   int    `json:"vcpu_count,omitempty"`
	MemMiB      int    `json:"mem_mib,omitempty"`
	CPUQuota    int    `json:"cpu_quota_percent,omitempty"`
	CGroupPath  string `json:"cgroup_path,omitempty"`
	ScratchByte int64  `json:"scratch_bytes,omitempty"`
	NetMbpsRx   int    `json:"net_mbps_rx,omitempty"`
	NetMbpsTx   int    `json:"net_mbps_tx,omitempty"`
	DiskIOPS    int    `json:"disk_iops,omitempty"`
	DiskMbps    int    `json:"disk_mbps,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	// WorkspaceHost is the directory the workspace was packed from. The image
	// path above says where the disk is; this says where it came from, which is
	// what a later process needs to write it back — a pause and the resume that
	// follows it are two processes, and neither is the one that packed it.
	WorkspaceHost string   `json:"workspace_host,omitempty"`
	Plugins       string   `json:"plugins,omitempty"`
	Allow         []string `json:"allow,omitempty"`
	RunDir        string   `json:"run_dir"`
	// Jailed is whether this machine's VMM ran under the jailer. It is in the
	// state and in the flight recorder because a record that does not say which
	// wall was around a run is a record that overstates the weaker one
	// (P5-1, the product owner's ruling of 2026-08-24).
	Jailed      bool      `json:"jailed"`
	StartedAt   time.Time `json:"started_at"`
	BootReadyMS int64     `json:"boot_ready_ms"`
	// Seccomp is the syscall-filter mode observed on the VMM's own threads once
	// the machine was answering — "filter", or the run was refused. It is read
	// from the host's /proc rather than inferred from the absence of a flag,
	// because a protection nobody has ever observed is a protection nobody has
	// (P5-2, docs/hardening.md §3).
	Seccomp        string `json:"seccomp,omitempty"`
	SeccompThreads int    `json:"seccomp_threads,omitempty"`
	// Profile is the confinement the guest reported applying to everything its
	// supervisor spawns: the flavor, the writable trees, the refused syscalls
	// (P5-3). Empty on a machine older than v0.9.
	Profile string `json:"profile,omitempty"`
}

// RecordSession is the flight recorder this sandbox's events belong in: the
// team's when it is in one, its own otherwise.
//
// It exists so no call site has to remember the rule. A team member whose
// commands landed in its own file would leave the team transcript with the
// messages but not the work they asked for, which is a transcript of half the
// story (E2-7).
func (s State) RecordSession() string {
	if s.Session != "" {
		return s.Session
	}
	return s.ID
}

// Sandbox is a running microVM.
type Sandbox struct {
	State    State
	api      *api
	opts     Options
	cmd      *exec.Cmd
	watchdog *os.Process
	// shutdownRefused is set when the shutdown handshake failed or was
	// refused: the write-back reads it and refuses to print success over an
	// unverified flush (ST-5.3 review, finding 3).
	shutdownRefused error
	readyLn         net.Listener
	eventsLn        net.Listener
	teamLn          net.Listener
	ready           chan proto.Ready
	done            chan struct{}
	waitErr         error
	// teamSem and eventsSem bound how many connections serveTeam and serveEvents
	// will service at once, the same shape internal/egress/proxy.go's Proxy.sem
	// was given for the identical problem (S5a): both listeners are reachable
	// directly over vsock by any process inside the guest, not only through the
	// supervisor's own well-behaved client, so an accept loop with nothing
	// upstream of it is a guest-controlled goroutine-per-connection budget (F5).
	// Created by listenTeam/listenEvents, before the goroutine that serves them
	// exists — making them inside that goroutine was a write racing every other
	// reader of the field (P7-16, D79). A Sandbox built without going through
	// either still zero-values cleanly, and the serve loops keep a nil check for
	// the fixtures that drive them directly.
	teamSem   chan struct{}
	eventsSem chan struct{}
	// profileError is why the guest could not confine what it spawns, when it
	// could not. Kept off State because it is a fault to report rather than a
	// fact to record: a machine that has one does not become a session.
	profileError string
}

const stateFile = "sandbox.json"

// New prepares a sandbox: it validates the image, creates the run directory,
// binds the host-side channels and writes the Firecracker configuration. It
// does not start anything.
//
// Binding before launch is not tidiness. The guest dials the ready channel the
// moment the supervisor is up; if the host socket does not exist yet, that
// connect is reset (docs/protocol.md §1.2) and the sandbox looks hung.
func New(opts Options) (*Sandbox, error) {
	if opts.Arch == "" {
		opts.Arch = HostArch()
	}
	if opts.Flavor == "" {
		opts.Flavor = "base"
	}
	if opts.ImageDir == "" {
		opts.ImageDir = ImageDir(opts.Arch)
	}
	if opts.VcpuCount == 0 {
		opts.VcpuCount = 2
	}
	if opts.MemMiB == 0 {
		opts.MemMiB = 512
	}

	kernelName, err := KernelArtifact(opts.Arch)
	if err != nil {
		return nil, err
	}
	kernel := filepath.Join(opts.ImageDir, kernelName)
	rootfs := filepath.Join(opts.ImageDir, "rootfs.ext4")
	for _, p := range []string{kernel, rootfs} {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("missing image artifact %s — run `make image ARCH=%s` first", p, opts.Arch)
		}
	}

	// The flavor is recorded in the audit trail, so it has to be checked
	// against the image rather than believed (D21).
	if err := checkManifest(opts.ImageDir, opts.Arch, opts.Flavor); err != nil {
		return nil, err
	}

	// Before anything is created, so a machine that cannot be jailed is refused
	// rather than half built (P5-1).
	if err := requireJail(opts); err != nil {
		return nil, err
	}
	id := opts.ID
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return nil, err
		}
	}
	runDir := jailRunDir(id)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}

	s := &Sandbox{
		opts:  opts,
		ready: make(chan proto.Ready, 1),
		done:  make(chan struct{}),
		State: State{
			ID:        id,
			Arch:      opts.Arch,
			Flavor:    opts.Flavor,
			UDSPath:   filepath.Join(runDir, "v.sock"),
			APIPath:   filepath.Join(runDir, "fc.sock"),
			RunDir:    runDir,
			StartedAt: time.Now(),
		},
	}

	cfg := firecrackerConfig(opts, kernel, rootfs, s.State.UDSPath, id)
	if opts.Workspace != nil {
		s.State.Workspace = opts.Workspace.ImagePath
		s.State.WorkspaceHost = opts.Workspace.HostDir
	}
	if opts.Plugins != nil {
		s.State.Plugins = opts.Plugins.ImagePath
	}
	s.State.Agent = opts.Agent
	s.State.Session = opts.Session
	s.State.VcpuCount = opts.VcpuCount
	s.State.MemMiB = opts.MemMiB
	s.State.ScratchByte = opts.ScratchBytes
	s.State.NetMbpsRx = opts.IO.NetMbpsRx
	s.State.NetMbpsTx = opts.IO.NetMbpsTx
	s.State.DiskIOPS = opts.IO.DiskIOPS
	s.State.DiskMbps = opts.IO.DiskMbps
	if opts.Net != nil {
		s.State.TAP = opts.Net.TAP
		s.State.HostIP = opts.Net.HostIP.String()
		s.State.GuestIP = opts.Net.GuestIP.String()
		s.State.Netmask = opts.Net.Netmask
		s.State.HostMAC = opts.Net.HostMAC
		s.State.ProxyPort = opts.Net.ProxyPort
		s.State.Allow = opts.Allow
	}
	// The jail is built before anything is written into it, because the run
	// directory *is* the chroot: config.json and the host's listening sockets
	// have to be inside it for the VMM to reach them (P5-1).
	s.State.Jailed = !opts.NoJail
	if s.State.Jailed {
		if cfg, err = stageJail(runDir, opts, kernel, rootfs, cfg); err != nil {
			s.cleanup()
			return nil, err
		}
	}
	blob, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		s.cleanup()
		return nil, fmt.Errorf("encode firecracker config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, "config.json"), blob, 0o600); err != nil {
		s.cleanup()
		return nil, fmt.Errorf("write firecracker config: %w", err)
	}

	ln, err := net.Listen("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortReady))
	if err != nil {
		s.cleanup()
		return nil, fmt.Errorf("bind ready channel: %w", err)
	}
	s.readyLn = ln
	go s.serveReady()
	if err := s.listenEvents(); err != nil {
		s.cleanup()
		return nil, err
	}
	if err := s.listenTeam(); err != nil {
		s.cleanup()
		return nil, err
	}
	s.api = newAPI(s.State.APIPath)

	return s, nil
}

// listenTeam binds the guest's team channel, and only for a sandbox that is in
// a team. A guest with no team dials nothing, and a guest whose host declined
// to answer would be worse than one that finds no listener: the second is a
// clear failure, the first is a hang.
func (s *Sandbox) listenTeam() error {
	if s.opts.OnTeamRequest == nil {
		return nil
	}
	ln, err := net.Listen("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortTeam))
	if err != nil {
		return fmt.Errorf("bind team channel: %w", err)
	}
	s.teamLn = ln
	// Created here rather than inside serveTeam. It used to be lazily made by
	// the serving goroutine itself, which is a write to a field of a struct the
	// starting goroutine keeps a pointer to — a data race the -race detector
	// reports on internal/sandbox's own concurrency fixtures, and one whose
	// losing outcome is two semaphores where the bound needs one (P7-16, D79).
	// The zero-value comment below stays true: a Sandbox that never goes
	// through here still has a nil channel, and serveTeam is never started for
	// it.
	s.teamSem = make(chan struct{}, maxConcurrentGuestConnections)
	go s.serveTeam()
	return nil
}

// maxConcurrentGuestConnections bounds how many connections serveTeam and
// serveEvents will each service at once — internal/egress/proxy.go's
// maxConcurrentConnections, mirrored here for the sibling listener that
// finding F5 pointed out never got it. A guest that opens far more
// connections than this to either channel cannot make either loop spawn more
// than this many goroutines, however many it opens or however long it holds
// them open without writing.
const maxConcurrentGuestConnections = 128

// guestFirstFrameTimeout bounds how long a newly accepted team or events
// connection may sit silent before it has sent one complete, parseable frame.
// It is cleared the moment that first frame is read, exactly like
// proxy.go's readHeaderTimeout is cleared once http.ReadRequest returns
// (S5a) — everything after that point is a legitimate, arbitrarily long idle
// gap between requests (teamClient.call in supervisor/team.go holds one
// connection open for the sandbox's whole life and calls it only when an
// agent has something to send), and punishing that would just make a working
// connection reconnect for no reason. What this bounds is the connection
// that never speaks at all: without it, a semaphore slot taken by one and
// never released would eventually be a slot never reclaimed, and the loop
// would stop accepting anyone else's connections for good (F5).
const guestFirstFrameTimeout = 10 * time.Second

// serveTeam answers the guest's team requests, one connection at a time per
// connection and strictly in order on each — the ordering the broker promises
// is per-edge FIFO, and answering out of order would break it on the way in
// rather than on the way out.
func (s *Sandbox) serveTeam() {
	if s.teamSem == nil {
		// A Sandbox assembled without listenTeam — a test fixture driving this
		// loop directly. listenTeam makes it before this goroutine exists, so
		// on every real path this is already non-nil and nothing is written
		// here (P7-16, D79).
		s.teamSem = make(chan struct{}, maxConcurrentGuestConnections)
	}
	for {
		// Acquired before Accept, not after, so the accept loop itself blocks
		// at capacity rather than merely queuing an ever-growing pile of
		// goroutines behind it (S5a).
		s.teamSem <- struct{}{}
		conn, err := s.teamLn.Accept()
		if err != nil {
			<-s.teamSem
			return
		}
		go func() {
			defer conn.Close()
			defer func() { <-s.teamSem }()
			r, w := proto.NewReader(conn), proto.NewWriter(conn)
			// Set before anything is read, so a connection that never sends a
			// frame is closed by the deadline rather than holding its
			// semaphore slot forever (F5). Cleared below the first time
			// r.Read succeeds.
			_ = conn.SetReadDeadline(time.Now().Add(guestFirstFrameTimeout))
			first := true
			for {
				var req proto.TeamRequest
				if err := r.Read(&req); err != nil {
					var syntax *json.SyntaxError
					var typ *json.UnmarshalTypeError
					if errors.As(err, &syntax) || errors.As(err, &typ) {
						// Same rule as the events channel: a frame that will
						// not parse is skipped, not fatal. Newline framing
						// means a bad line cannot desynchronise the stream.
						continue
					}
					return
				}
				if first {
					_ = conn.SetReadDeadline(time.Time{})
					first = false
				}
				// Before the broker acts on it, because acting on it is what
				// makes it unrecoverable: a message the broker accepts is a
				// message taken off somebody's mailbox when it is read, and if
				// the frame that would deliver it cannot be written there is
				// nothing left to deliver (M-8).
				if refusal := refuseUnanswerable(req); refusal != nil {
					if err := w.Write(refusal); err != nil {
						return
					}
					continue
				}
				resp := s.opts.OnTeamRequest(req)
				resp.V, resp.ID = proto.Version, req.ID
				if err := w.Write(resp); err != nil {
					if !errors.Is(err, proto.ErrLineTooLong) {
						return
					}
					// An answer too large for the channel is the one send
					// failure that is not a dead connection: proto.Writer
					// measures the whole frame before it writes any of it, so
					// none of the refused answer reached the wire and the
					// stream is still on a frame boundary. The same recovery
					// the guest's MCP session already makes (supervisor/mcp.go).
					//
					// The check above makes this unreachable for a body an
					// agent sent, which is the point of keeping it: it is what
					// stops a field added to the envelope later from quietly
					// bringing back the destroyed message and the unexplained
					// EOF, and it still answers for a body that reached the
					// broker some other way.
					if err := w.Write(tooLargeToAnswer(req)); err != nil {
						return
					}
				}
			}
		}()
	}
}

// refuseUnanswerable is the refusal for a team request the host could not
// answer inside one frame, or nil when there is nothing wrong with it.
//
// Both limits are on what the guest chose, and both are refused rather than
// trimmed: a request answered with a truncated body or under an id that is not
// the one asked with is a request answered wrongly, and the agent that sent it
// can act on a size it is told (the shape internal/team already refuses an
// oversized store value with).
func refuseUnanswerable(req proto.TeamRequest) *proto.TeamResponse {
	if len(req.ID) > proto.MaxTeamID {
		// Answered under the id's first MaxTeamID bytes: it is not the id that
		// was asked with — nothing here can be — but it is enough of it for the
		// caller to see which request was refused, and it is bounded.
		return &proto.TeamResponse{
			V: proto.Version, ID: req.ID[:proto.MaxTeamID],
			Error: &proto.Error{Kind: proto.ErrBadRequest, Message: fmt.Sprintf(
				"a request id may be at most %d bytes; this one is %d",
				proto.MaxTeamID, len(req.ID))},
		}
	}
	if n := base64Size(req.Body); n > proto.MaxTeamBody {
		return &proto.TeamResponse{
			V: proto.Version, ID: req.ID,
			Error: &proto.Error{Kind: proto.ErrBadRequest, Message: fmt.Sprintf(
				"a team message may carry at most %d bytes; this one is %d",
				proto.MaxTeamBody, n)},
		}
	}
	// The store key travels on this same envelope (proto.TeamRequest.Key) for
	// store_get and store_put, and internal/team already has a bound for it —
	// MaxKeyBytes — but nothing on this side of the wire enforced it before
	// OnTeamRequest ever saw the request, unlike the id and the body just
	// above. Checked here rather than duplicated as a second constant, so the
	// two bounds cannot drift apart (S5b).
	if len(req.Key) > team.MaxKeyBytes {
		return &proto.TeamResponse{
			V: proto.Version, ID: req.ID,
			Error: &proto.Error{Kind: proto.ErrBadRequest, Message: fmt.Sprintf(
				"a store key may be at most %d bytes; this one is %d",
				team.MaxKeyBytes, len(req.Key))},
		}
	}
	return nil
}

// tooLargeToAnswer stands in for an answer the channel will not carry. It names
// the frame limit, because the size of an answer is a reason a caller can act
// on and a closed connection is not.
//
// Everything in it is the host's own text but the id, which the caller needs to
// know which request was refused and which the check above has already bounded
// — so this frame is always writable, which a refusal has to be.
func tooLargeToAnswer(req proto.TeamRequest) proto.TeamResponse {
	return proto.TeamResponse{
		V: proto.Version, ID: req.ID,
		Error: &proto.Error{Kind: proto.ErrInternal, Message: fmt.Sprintf(
			"the answer to this request does not fit a %d byte frame", proto.MaxLine)},
	}
}

// base64Size is how many bytes a base64 string decodes to, worked out from its
// length rather than by decoding it — the string being measured is up to a
// megabyte, and this runs before anything has agreed to spend that.
func base64Size(s string) int {
	n := base64.StdEncoding.DecodedLen(len(s))
	switch {
	case strings.HasSuffix(s, "=="):
		n -= 2
	case strings.HasSuffix(s, "="):
		n--
	}
	if n < 0 {
		return 0
	}
	return n
}

// listenEvents binds the guest's events channel. It has to exist before the VM
// starts: the guest dials it as soon as the supervisor is up, and a host that is
// not listening yet turns the guest's first connect into a reset it can only
// recover from by retrying (docs/protocol.md §2).
func (s *Sandbox) listenEvents() error {
	ln, err := net.Listen("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortEvents))
	if err != nil {
		return fmt.Errorf("bind events channel: %w", err)
	}
	s.eventsLn = ln
	// Same as listenTeam's: made by the goroutine that starts the server, not
	// by the one that serves it (P7-16, D79).
	s.eventsSem = make(chan struct{}, maxConcurrentGuestConnections)
	go s.serveEvents()
	return nil
}

// serveEvents reads guest-reported events and hands them to the caller. The
// guest reconnects after a drop, so this keeps accepting; nothing here trusts
// the frames beyond their shape, because the guest runs untrusted code and this
// is a report, not a record.
func (s *Sandbox) serveEvents() {
	if s.eventsSem == nil {
		// Same as serveTeam's: only a fixture that assembled a Sandbox without
		// listenEvents reaches this (P7-16, D79).
		s.eventsSem = make(chan struct{}, maxConcurrentGuestConnections)
	}
	for {
		// Same reasoning as serveTeam's semaphore: acquired before Accept so a
		// guest that opens far more connections than this cannot make this
		// loop spawn more than maxConcurrentGuestConnections goroutines (F5).
		s.eventsSem <- struct{}{}
		conn, err := s.eventsLn.Accept()
		if err != nil {
			<-s.eventsSem
			return
		}
		go func() {
			defer conn.Close()
			defer func() { <-s.eventsSem }()
			r := proto.NewReader(conn)
			// Same reasoning as serveTeam's: bounds a connection that never
			// sends a parseable frame, cleared the first time one arrives so a
			// guest that reports events sparsely over the sandbox's life is
			// never punished for the gaps (F5).
			_ = conn.SetReadDeadline(time.Now().Add(guestFirstFrameTimeout))
			first := true
			for {
				var ev proto.GuestEvent
				if err := r.Read(&ev); err != nil {
					// A frame that will not parse is skipped rather than fatal.
					// Framing is newline-delimited, so a bad line cannot
					// desynchronise the stream — and letting one malformed
					// frame silence every later report would hand an untrusted
					// guest a way to go quiet on purpose. A frame past the
					// length limit is different: docs/protocol.md §3 makes that
					// fatal for the connection, and the guest will re-dial.
					var syntax *json.SyntaxError
					var typ *json.UnmarshalTypeError
					if errors.As(err, &syntax) || errors.As(err, &typ) {
						continue
					}
					return
				}
				if first {
					_ = conn.SetReadDeadline(time.Time{})
					first = false
				}
				if s.opts.OnGuestEvent != nil {
					s.opts.OnGuestEvent(ev)
				}
			}
		}()
	}
}

// Start launches Firecracker and returns once the process is running. It does
// not wait for the guest — use WaitReady for that.
func (s *Sandbox) Start(ctx context.Context) error {
	// The API socket is always present now, even for a machine that will never
	// be snapshotted: pause, create and load all go through it, and a sandbox
	// that cannot be snapshotted later because of how it was started is a
	// surprise nobody wants at the moment they need it.
	argv := []string{"firecracker",
		"--api-sock", s.State.APIPath,
		"--config-file", filepath.Join(s.State.RunDir, "config.json")}
	if s.State.Jailed {
		// Chroot-relative, because that is the filesystem the VMM will see.
		// The host keeps its own absolute paths to the same two files.
		argv = jailArgv(s.State.ID, s.opts.CPUSlice, []string{
			"--api-sock", inJail("fc.sock"),
			"--config-file", inJail("config.json")})
	}
	// Under systemd this prefixes the command with the scope request; on the
	// direct path it is unchanged (F-D11). It wraps the jailer as readily as it
	// wraps Firecracker, and it has to: the scope is the only thing that puts
	// the VMM in a cgroup on a machine that resolves to the systemd path, and
	// skipping it here is what made --cpu-quota refuse every jailed run (P5-6).
	argv = s.opts.CPUSlice.WrapArgv(argv)
	cmd := exec.Command(argv[0], argv[1:]...)
	// Its own process group, so a Ctrl-C delivered to the whole foreground
	// group does not race our orderly shutdown. Pdeathsig takes the direct
	// child down with this process — the unjailed VMM entirely, the jailed
	// one's sudo wrapper — and the watchdog (spawned below, once the pid is
	// known) covers the rest of that chain (ST-5.3).
	// See spawnattr_linux.go for the PDEATHSIG reasoning and the
	// LockOSThread invariant this construction relies on.
	cmd.SysProcAttr = vmmSpawnAttr(syscall.SIGKILL)
	// On the direct path, place it in its cgroup at clone time rather than
	// moving it once it is already running: a quota that starts a moment late
	// is a quota with a hole in it (E1-2).
	// Clone-time cgroup placement is the direct path's, and it is not available
	// through the jailer, which forks: there the cgroup is named with
	// --parent-cgroup instead (jail.go).
	if s.opts.CPUSlice.Direct() && !s.State.Jailed {
		placeInCgroup(cmd, s.opts.CPUSlice.FD())
	}
	if s.opts.CPUSlice != nil {
		s.State.CPUQuota = s.opts.CPUSlice.Percent
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("firecracker stdout: %w", err)
	}
	cmd.Stderr = cmd.Stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start firecracker (is it on PATH?): %w", err)
	}
	s.cmd = cmd
	s.spawnVMMWatchdog()
	s.State.PID = cmd.Process.Pid
	if s.State.Jailed {
		// Our own child is sudo; the VMM is its grandchild after the jailer
		// execs. Everything host-side that wants the VMM — its cgroup, its
		// seccomp mode, a signal — wants the pid the jailer wrote down.
		pid, err := jailedPID(s.State.RunDir)
		if err != nil {
			_ = s.Shutdown(2 * time.Second)
			return err
		}
		s.State.PID = pid
	} else {
		// The unjailed VMM writes no pid file of its own (the jailer's is the
		// only writer on the jailed path), and the watchdog reads this exact
		// file — write it so --no-jail has the same protection (review,
		// finding 8).
		_ = os.WriteFile(filepath.Join(s.State.RunDir, "firecracker.pid"),
			[]byte(strconv.Itoa(s.State.PID)), 0o644)
	}
	go s.drainConsole(stdout)
	go func() {
		s.waitErr = cmd.Wait()
		close(s.done)
	}()
	// Read the quota back rather than trusting that asking for it worked.
	if s.opts.CPUSlice != nil {
		if err := s.opts.CPUSlice.Confirm(s.State.PID); err != nil {
			_ = s.Shutdown(2 * time.Second)
			return err
		}
		// Recorded because the quota is only a claim until someone can go and
		// read cpu.stat for themselves (E1-7, E1-8).
		s.State.CGroupPath = s.opts.CPUSlice.Path
	}
	return s.writeState()
}

// WaitReady blocks until the guest announces itself or the context expires. The
// host times this itself and never trusts the guest's clock (docs/protocol.md §5.3).
func (s *Sandbox) WaitReady(ctx context.Context) (proto.Ready, error) {
	select {
	case r := <-s.ready:
		s.State.BootReadyMS = time.Since(s.State.StartedAt).Milliseconds()
		// After the number is taken, so the bar measures the machine and not
		// the checking of it, and after the guest is answering, so every one of
		// the VMM's threads has reached the point where it installs its filter
		// (P5-2). confirmSeccomp writes the state itself.
		if err := s.confirmSeccomp(); err != nil {
			_ = s.Shutdown(2 * time.Second)
			return proto.Ready{}, err
		}
		// The guest's own report of whether it can confine what it spawns. It
		// is a claim rather than an observation — the host cannot read the
		// guest's kernel — so it is the fail-closed switch and not the proof;
		// the proof is that a write outside the profile is refused, which
		// dev/accept-profile.sh checks by doing it (P5-3).
		if r.ProfileError != "" {
			_ = s.Shutdown(2 * time.Second)
			return proto.Ready{}, denial.ProfileNotEnforced.Err(denial.V{"reason": proto.SafeText(r.ProfileError)})
		}
		// An image older than this CLI reports no profile at all. Not refused,
		// for D32's reason — the host walls are unchanged and every image built
		// before v0.9 would otherwise stop booting — but never silent, because
		// a run that confines nothing must not read like one that does (P5-4).
		if w := postureWarning(fromImage, r.Profile, ""); w != "" {
			warnf("%s", w)
		}
		s.State.Profile = proto.SafeText(r.Profile)
		if err := s.writeState(); err != nil {
			return proto.Ready{}, err
		}
		return r, nil
	case <-s.done:
		return proto.Ready{}, fmt.Errorf("firecracker exited before the guest was ready: %w", s.waitErr)
	case <-ctx.Done():
		return proto.Ready{}, ctx.Err()
	}
}

// InstallTrustAnchor hands the guest the egress CA's certificate over the
// control channel, so TLS termination for secret-bound domains is trusted
// inside the sandbox.
//
// It happens after the guest is ready rather than at image build time because
// the CA is minted per run and never persisted, and after the overlay is up
// because the rootfs is read-only (decision D6).
func (s *Sandbox) InstallTrustAnchor(pemData []byte) error {
	conn, err := Connect(s.State.UDSPath, proto.PortControl, 10*time.Second)
	if err != nil {
		return fmt.Errorf("install trust anchor: %w", err)
	}
	defer conn.Close()

	if err := proto.NewWriter(conn).Write(proto.ControlRequest{
		V: proto.Version, ID: "trust", Op: proto.OpTrust, CAPEM: string(pemData),
	}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp proto.ControlResponse
	if err := proto.NewReader(conn).Read(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("guest refused the trust anchor: %v", resp.Error)
	}
	return nil
}

// Snapshot pauses the microVM, writes its state and memory, and resumes it.
//
// The machine is paused for the duration, which is the honest cost of a
// consistent snapshot: memory has to stop changing while it is copied.
func (s *Sandbox) Snapshot(dir string) (statePath, memPath string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	statePath = filepath.Join(dir, "state")
	memPath = filepath.Join(dir, "memory")

	// A jailed VMM can only create files inside its own chroot, so it writes
	// them there and the host moves them out afterwards. Asking it for a path
	// it cannot open is how this first failed (P5-1).
	askState, askMem := statePath, memPath
	if s.State.Jailed {
		askState, askMem = inJail(jailSnapState), inJail(jailSnapMem)
	}

	if err := s.api.pause(); err != nil {
		return "", "", err
	}
	if err := s.api.createSnapshot(askState, askMem); err != nil {
		// Leave the machine running rather than paused: a failed snapshot
		// should cost a snapshot, not the session.
		_ = s.api.resume()
		return "", "", err
	}
	if err := s.api.resume(); err != nil {
		return "", "", err
	}
	if s.State.Jailed {
		for _, m := range []struct{ from, to string }{
			{filepath.Join(s.State.RunDir, jailSnapState), statePath},
			{filepath.Join(s.State.RunDir, jailSnapMem), memPath},
		} {
			if err := linkInto(m.from, m.to); err != nil {
				return "", "", fmt.Errorf("bring the snapshot out of the jail: %w", err)
			}
			_ = os.Remove(m.from)
		}
	}
	restrictSnapshot(statePath, memPath)
	return statePath, memPath, nil
}

// restrictSnapshot takes the group and world bits off a snapshot.
//
// Firecracker creates these files itself, so their mode is whatever the process
// umask allowed — 0664 on an ordinary machine. The directory above them is
// 0700 and that is what actually keeps them private today, but a *memory image
// of a booted guest* should not be one chmod away from being readable: it is
// the most sensitive file this program writes, and the only reason it is
// currently harmless is that nothing has yet been in that guest's memory.
// Failures are ignored on purpose — a snapshot that exists with a wider mode
// than intended is better than no snapshot, and the directory still covers it.
func restrictSnapshot(paths ...string) {
	for _, p := range paths {
		_ = os.Chmod(p, 0o600)
	}
}

// SnapshotRunning snapshots a sandbox this process did not start, by talking to
// its API socket directly. `kelyfos snapshot save` is a separate invocation from
// the `kelyfos run` holding the machine open, so it has no Sandbox to call.
// SnapshotMeta travels with a snapshot so a later restore knows what the machine
// was, rather than making the caller remember.
type SnapshotMeta struct {
	Arch   string `json:"arch"`
	Flavor string `json:"flavor"`
	// VcpuCount and MemMiB are what the frozen machine holds. A restore cannot
	// change them: Firecracker takes the machine configuration from the state
	// file, not from the options it is handed. They are recorded so a door with
	// a ceiling to enforce has something to check against, rather than
	// discovering afterwards that it just restored a machine twice the size its
	// policy allows (E4-2).
	VcpuCount    int  `json:"vcpu_count,omitempty"`
	MemMiB       int  `json:"mem_mib,omitempty"`
	HasWorkspace bool `json:"has_workspace"`
	// WorkspacePath is where the workspace disk lived when the snapshot was
	// taken. It has to be recorded because Firecracker insists that a block
	// device's backing file exists at its original path before a snapshot will
	// load at all — the drive can only be repointed afterwards.
	WorkspacePath string `json:"workspace_path,omitempty"`
	WorkspaceSize int64  `json:"workspace_size,omitempty"`
	// HasPlugins and PluginsPath are the read-only plugins device, recorded for
	// the same reason the workspace is: Firecracker will not load a snapshot
	// until every block device's backing file is present at the path recorded
	// in it. Unlike the workspace there is no per-fork copy, because the device
	// is read-only — every fork can read the one file, and none of them can
	// change it (E4-6).
	HasPlugins  bool   `json:"has_plugins,omitempty"`
	PluginsPath string `json:"plugins_path,omitempty"`
	// HasNetwork records that the machine had a NIC when it was frozen. The
	// TAP itself is deliberately not recorded: it will not exist at restore
	// time and re-using its name would collide with a live sandbox. What the
	// restore needs is only that a NIC must be re-paired, which interface, and
	// what the machine was allowed to reach (D22).
	HasNetwork bool     `json:"has_network,omitempty"`
	IfaceID    string   `json:"iface_id,omitempty"`
	Allow      []string `json:"allow,omitempty"`
	// The addressing travels with the snapshot too. The guest's HTTPS_PROXY
	// points at HostIP:ProxyPort and lives inside the memory image, so a
	// restore that picked new numbers would come up with working plumbing and
	// a guest still dialling where the proxy used to be.
	HostIP    string `json:"host_ip,omitempty"`
	GuestIP   string `json:"guest_ip,omitempty"`
	Netmask   string `json:"netmask,omitempty"`
	HostMAC   string `json:"host_mac,omitempty"`
	ProxyPort int    `json:"proxy_port,omitempty"`
	// SourceSession is the chain the frozen machine's events belonged to —
	// State.RecordSession() at the moment it was frozen, which is the
	// machine's own id outside a team and the team's id inside one. A
	// restore or fork reads it back to populate session.policy's
	// parent_session (P7-2, docs/policy-record.md §5), which is what makes
	// "a snapshot name is not a session id" stop being true: before this, the
	// only record of where a restored machine came from was the prose in its
	// session.start's reason field, and a name cannot be followed back across
	// a second hop the way an id can. Empty on a snapshot taken before this
	// field existed, which restores exactly as it always did — parent_session
	// is simply absent, the same as any other field an older snapshot never
	// wrote.
	SourceSession string `json:"source_session,omitempty"`
}

func snapshotMetaPath(dir string) string  { return filepath.Join(dir, "meta.json") }
func snapshotPlugins(dir string) string   { return filepath.Join(dir, "plugins.ext4") }
func snapshotWorkspace(dir string) string { return filepath.Join(dir, "workspace.ext4") }

// ReadSnapshotMeta loads what was recorded alongside a snapshot.
// WriteSnapshotMeta records what a snapshot is, for a caller that took one
// through (*Sandbox).Snapshot rather than through SnapshotRunning — which is
// the team's fork template (E2-9). Without it a restore has nothing to say
// about the machine it is loading, and a snapshot with no metadata is treated
// as one with no network and no workspace, which is true here and must be true
// on purpose rather than by omission.
func WriteSnapshotMeta(dir string, meta SnapshotMeta) error {
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(snapshotMetaPath(dir), blob, 0o600)
}

func ReadSnapshotMeta(dir string) (*SnapshotMeta, error) {
	blob, err := os.ReadFile(snapshotMetaPath(dir))
	if err != nil {
		// A snapshot from before metadata existed is still restorable; it just
		// has nothing to say about itself.
		if os.IsNotExist(err) {
			return &SnapshotMeta{}, nil
		}
		return nil, err
	}
	var meta SnapshotMeta
	if err := json.Unmarshal(blob, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func SnapshotRunning(st *State, dir string) (statePath, memPath string, err error) {
	if st.APIPath == "" {
		return "", "", fmt.Errorf("sandbox %s was started by an older kelyfos with no API socket", st.ID)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	statePath = filepath.Join(dir, "state")
	memPath = filepath.Join(dir, "memory")

	// The same rule as (*Sandbox).Snapshot: a jailed VMM can only create files
	// inside its own chroot, so it writes them there and the host moves them
	// out. This is the path `kelyfos snapshot save` and `pause` take, from a
	// process that did not start the machine (P5-1).
	askState, askMem := statePath, memPath
	if st.Jailed {
		askState, askMem = inJail(jailSnapState), inJail(jailSnapMem)
	}

	a := newAPI(st.APIPath)
	if err := a.pause(); err != nil {
		return "", "", err
	}
	if err := a.createSnapshot(askState, askMem); err != nil {
		_ = a.resume()
		return "", "", err
	}
	if st.Jailed {
		for _, m := range []struct{ from, to string }{
			{filepath.Join(st.RunDir, jailSnapState), statePath},
			{filepath.Join(st.RunDir, jailSnapMem), memPath},
		} {
			if err := linkInto(m.from, m.to); err != nil {
				_ = a.resume()
				return "", "", fmt.Errorf("bring the snapshot out of the jail: %w", err)
			}
			_ = os.Remove(m.from)
		}
	}

	meta := SnapshotMeta{Arch: st.Arch, Flavor: st.Flavor, VcpuCount: st.VcpuCount, MemMiB: st.MemMiB,
		SourceSession: st.RecordSession()}
	if st.TAP != "" {
		meta.HasNetwork = true
		meta.IfaceID = "eth0"
		meta.Allow = st.Allow
		meta.HostIP = st.HostIP
		meta.GuestIP = st.GuestIP
		meta.Netmask = st.Netmask
		meta.HostMAC = st.HostMAC
		meta.ProxyPort = st.ProxyPort
	}
	if st.Plugins != "" {
		// stageFile rather than copyFile: the captured device is left read-only,
		// so a second snapshot under the same name would otherwise be refused
		// by the file the first one wrote.
		if err := stageFile(st.Plugins, snapshotPlugins(dir)); err != nil {
			_ = a.resume()
			return "", "", fmt.Errorf("capture plugins: %w", err)
		}
		meta.HasPlugins, meta.PluginsPath = true, st.Plugins
	}
	if st.Workspace != "" {
		// The workspace disk is part of the machine's state, so it travels with
		// the snapshot. Copying it while the VM is paused is what makes the copy
		// consistent with the memory image.
		if err := copyFile(st.Workspace, snapshotWorkspace(dir)); err != nil {
			copyWorkspaceManifest(st.Workspace, snapshotWorkspace(dir))
			_ = a.resume()
			return "", "", fmt.Errorf("capture workspace: %w", err)
		}
		if info, err := os.Stat(snapshotWorkspace(dir)); err == nil {
			meta.HasWorkspace = true
			meta.WorkspacePath = st.Workspace
			meta.WorkspaceSize = info.Size()
		}
	}
	blob, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(snapshotMetaPath(dir), blob, 0o600); err != nil {
		_ = a.resume()
		return "", "", err
	}
	restrictSnapshot(statePath, memPath)
	return statePath, memPath, a.resume()
}

// Resync repairs what a restored guest is wrong about: the wall clock, which
// still reads what it did when the snapshot was taken, and the random pool,
// which holds exactly the state it held then (docs/protocol.md §5.4).
//
// For a single restore that is stale. For N forks of one snapshot it is worse:
// every fork starts with an identical pool, so every fork generates the same
// "random" bytes.
func (s *Sandbox) Resync() error {
	conn, err := Connect(s.State.UDSPath, proto.PortControl, 10*time.Second)
	if err != nil {
		return fmt.Errorf("resync: %w", err)
	}
	defer conn.Close()

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	if err := proto.NewWriter(conn).Write(proto.ControlRequest{
		V: proto.Version, ID: "resync", Op: proto.OpResync,
		RealtimeNS: time.Now().UnixNano(),
		Entropy:    base64.StdEncoding.EncodeToString(seed),
	}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp proto.ControlResponse
	if err := proto.NewReader(conn).Read(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("guest refused resync: %v", resp.Error)
	}
	// A restored machine sends no ready frame, so this round trip — which the
	// restore already makes, and which is the proof the machine is answering —
	// is also where the host learns what the guest confines (P5-7).
	s.State.Profile = proto.SafeText(resp.Profile)
	s.profileError = proto.SafeText(resp.ProfileError)
	return nil
}

// Restore brings a machine back from a snapshot into a fresh run directory.
//
// The snapshot is loaded without resuming, so the guest is still frozen when
// vsock_override has taken effect and the host's channels are bound — then it is
// resumed and resynced. Resuming first would let the guest run for a moment
// believing a stale clock, which is exactly the window that produces duplicate
// "random" values across forks.
func Restore(snapDir string, opts Options) (*Sandbox, time.Duration, error) {
	statePath := filepath.Join(snapDir, "state")
	memPath := filepath.Join(snapDir, "memory")
	for _, p := range []string{statePath, memPath} {
		if _, err := os.Stat(p); err != nil {
			return nil, 0, fmt.Errorf("snapshot is incomplete: %w", err)
		}
	}

	if err := requireJail(opts); err != nil {
		return nil, 0, err
	}
	id := opts.ID
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return nil, 0, err
		}
	}
	runDir := jailRunDir(id)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return nil, 0, err
	}

	s := &Sandbox{
		opts:  opts,
		ready: make(chan proto.Ready, 1),
		done:  make(chan struct{}),
		State: State{
			ID: id, Arch: opts.Arch, Flavor: opts.Flavor,
			UDSPath: filepath.Join(runDir, "v.sock"),
			APIPath: filepath.Join(runDir, "fc.sock"),
			RunDir:  runDir, StartedAt: time.Now(), Jailed: !opts.NoJail,
			// Carried from the options rather than from the memory image,
			// because the image is shared: every fork of one snapshot has the
			// same machine baked into it and a different job in the team. The
			// host is the side that knows which fork is which agent (E2-9).
			Agent: opts.Agent, Session: opts.Session,
			VcpuCount: opts.VcpuCount, MemMiB: opts.MemMiB,
			ScratchByte: opts.ScratchBytes,
		},
	}
	// The guest's channels must exist before it runs again: a restored guest
	// reconnects its outbound channels immediately (docs/protocol.md §1.6).
	ln, err := net.Listen("unix", fmt.Sprintf("%s_%d", s.State.UDSPath, proto.PortReady))
	if err != nil {
		s.cleanup()
		return nil, 0, err
	}
	s.readyLn = ln
	go s.serveReady()
	if err := s.listenEvents(); err != nil {
		s.cleanup()
		return nil, 0, err
	}
	// A forked team member dials its team channel the moment it resumes, and
	// without this there is nothing on the other end — the fork would come up
	// as a machine in a team that could not speak to it.
	if err := s.listenTeam(); err != nil {
		s.cleanup()
		return nil, 0, err
	}
	s.api = newAPI(s.State.APIPath)

	started := time.Now()
	argv := []string{"firecracker", "--api-sock", s.State.APIPath}
	if s.State.Jailed {
		argv = jailArgv(s.State.ID, s.opts.CPUSlice,
			[]string{"--api-sock", inJail("fc.sock")})
	}
	// After the jailer wrapping rather than instead of it, for the reason in
	// Start: on the systemd path the scope is what places the VMM (P5-6).
	argv = s.opts.CPUSlice.WrapArgv(argv)
	cmd := exec.Command(argv[0], argv[1:]...)
	// Pdeathsig: the same reasoning Start has (ST-5.3).
	// See spawnattr_linux.go for the PDEATHSIG reasoning and the
	// LockOSThread invariant this construction relies on.
	cmd.SysProcAttr = vmmSpawnAttr(syscall.SIGKILL)
	// The same placement a cold boot gets: at clone time on the direct path, so
	// a quota that starts a moment late is not a quota with a hole in it (E1-2)
	// — except through the jailer, which forks and is told the parent cgroup.
	if s.opts.CPUSlice.Direct() && !s.State.Jailed {
		placeInCgroup(cmd, s.opts.CPUSlice.FD())
	}
	if s.opts.CPUSlice != nil {
		s.State.CPUQuota = s.opts.CPUSlice.Percent
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		s.cleanup()
		return nil, 0, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		s.cleanup()
		return nil, 0, err
	}
	s.cmd = cmd
	s.spawnVMMWatchdog()
	s.State.PID = cmd.Process.Pid
	if s.State.Jailed {
		pid, err := jailedPID(s.State.RunDir)
		if err != nil {
			_ = s.Shutdown(2 * time.Second)
			return nil, 0, err
		}
		s.State.PID = pid
	}
	go s.drainConsole(stdout)
	go func() { s.waitErr = cmd.Wait(); close(s.done) }()

	wait := 30 * time.Second
	if opts.ReadyTimeout > 0 {
		wait = opts.ReadyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	if err := s.api.waitReady(ctx); err != nil {
		_ = s.Shutdown(2 * time.Second)
		return nil, 0, err
	}
	// Read the quota back rather than trusting that asking for it worked, and
	// before the machine resumes rather than after.
	if s.opts.CPUSlice != nil {
		if err := s.opts.CPUSlice.Confirm(s.State.PID); err != nil {
			_ = s.Shutdown(2 * time.Second)
			return nil, 0, err
		}
		s.State.CGroupPath = s.opts.CPUSlice.Path
	}
	// Firecracker will not load a snapshot unless every block device's backing
	// file is present at the path recorded in it — the drive can only be
	// repointed after the load succeeds. So the captured workspace is put back
	// where it was first, purely so the load has something to open; each fork
	// then swaps in its own copy before the machine is resumed, and no guest
	// I/O happens in between.
	meta, metaErr := ReadSnapshotMeta(snapDir)
	if metaErr == nil && meta.HasPlugins && meta.PluginsPath != "" {
		// Staged back and then left alone. The plugins device is read-only, so
		// every fork of one snapshot can share the single file: there is
		// nothing for them to race over and nothing to repoint afterwards.
		if _, err := os.Stat(meta.PluginsPath); os.IsNotExist(err) {
			if err := stageFile(snapshotPlugins(snapDir), meta.PluginsPath); err != nil {
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("stage plugins for snapshot load: %w", err)
			}
		}
		s.State.Plugins = meta.PluginsPath
	}
	if metaErr == nil && meta.HasWorkspace && meta.WorkspacePath != "" {
		if _, err := os.Stat(meta.WorkspacePath); os.IsNotExist(err) {
			if err := copyFile(snapshotWorkspace(snapDir), meta.WorkspacePath); err != nil {
				copyWorkspaceManifest(snapshotWorkspace(snapDir), meta.WorkspacePath)
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("stage workspace for snapshot load: %w", err)
			}
		}
	}

	// A machine frozen with a NIC cannot be loaded until that NIC has somewhere
	// to attach. The TAP it was taken with is long gone, so it is re-paired to
	// the one this restore just created (D22).
	// The jailed VMM opens these by the only paths it has: its own. The files
	// are linked into the chroot first — hard links on the same filesystem, so
	// a restore does not copy a memory image to read it (P5-1).
	//
	// The devices go in too, and that is not optional: a snapshot taken from a
	// jailed machine records its drives at chroot-relative paths, and
	// Firecracker will not load one until every backing file is present at the
	// path written in it. The rootfs is /rootfs.ext4 inside both jails, which
	// is exactly why it works — the recorded path is portable precisely because
	// it is not a host path.
	loadState, loadMem, loadUDS := statePath, memPath, s.State.UDSPath
	if s.State.Jailed {
		staged := []struct{ src, name string }{
			{statePath, jailSnapState},
			{memPath, jailSnapMem},
		}
		// A restore is given no image directory — it boots from memory, not
		// from a kernel — so it is resolved here the way a cold boot resolves
		// it, from the architecture the snapshot recorded.
		imageDir := opts.ImageDir
		if imageDir == "" {
			imageDir = ImageDir(opts.Arch)
		}
		if kernelName, err := KernelArtifact(opts.Arch); err == nil {
			staged = append(staged,
				struct{ src, name string }{filepath.Join(imageDir, kernelName), defaultJailNames().Kernel},
				struct{ src, name string }{filepath.Join(imageDir, "rootfs.ext4"), defaultJailNames().Rootfs},
				// The same rootfs a second time, at the host path a snapshot
				// taken before P5-1 recorded. Firecracker opens a drive's
				// backing file by the path written in the state file, and an
				// older snapshot's is absolute; without this every template and
				// every saved machine from before the jail would stop
				// restoring. Found by the three-agent recipe, whose cached
				// template predates the change.
				struct{ src, name string }{
					filepath.Join(imageDir, "rootfs.ext4"),
					strings.TrimPrefix(filepath.Join(imageDir, "rootfs.ext4"), "/")})
		}
		if opts.Plugins != nil {
			staged = append(staged, struct{ src, name string }{opts.Plugins.ImagePath, defaultJailNames().Plugins})
		}
		// The workspace, and by copy rather than by link (P5-9).
		//
		// A snapshot of a machine that had one records its drive at the
		// chroot-relative /workspace.ext4, and Firecracker will not load a
		// snapshot until every backing file is present at the path written in
		// it — so this has to happen before the load, not after. Before P5-1 the
		// recorded path was an absolute host one that still existed, which is
		// why the staging below the load was enough and why nothing noticed:
		// no suite snapshots a machine with a workspace.
		//
		// A copy, because this file is the machine's own from here on. Two forks
		// of one snapshot that hard-linked it would write into the same blocks,
		// which is the "independent fork" claim being false in the most damaging
		// possible way (P3-2).
		if metaErr == nil && meta.HasWorkspace {
			dest := filepath.Join(s.State.RunDir, defaultJailNames().Workspace)
			if err := copyFile(snapshotWorkspace(snapDir), dest); err != nil {
				copyWorkspaceManifest(snapshotWorkspace(snapDir), dest)
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("stage the workspace into the jail: %w", err)
			}
		}
		for _, f := range staged {
			dest := filepath.Join(s.State.RunDir, f.name)
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, err
			}
			if err := linkInto(f.src, dest); err != nil {
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("stage the snapshot into the jail: %w", err)
			}
		}
		loadState, loadMem = inJail(jailSnapState), inJail(jailSnapMem)
		loadUDS = inJail(defaultJailNames().Vsock)
	}
	load := snapshotLoad{
		SnapshotPath:  loadState,
		MemBackend:    memBackend{BackendPath: loadMem, BackendType: "File"},
		ResumeVM:      false,
		VsockOverride: &vsockOverride{UDSPath: loadUDS},
	}
	if metaErr == nil && meta.HasNetwork {
		if opts.Net == nil {
			_ = s.Shutdown(2 * time.Second)
			return nil, 0, fmt.Errorf(
				"this snapshot was taken from a sandbox with egress (allowed: %s), so it needs a network to restore into.\n"+
					"    restore it with:  kelyfos snapshot restore --allow %s",
				strings.Join(meta.Allow, ","), strings.Join(meta.Allow, ","))
		}
		iface := meta.IfaceID
		if iface == "" {
			iface = "eth0"
		}
		load.NetworkOverrides = []networkOverride{{IfaceID: iface, HostDevName: opts.Net.TAP}}
		s.State.TAP = opts.Net.TAP
		s.State.HostIP = opts.Net.HostIP.String()
		s.State.GuestIP = opts.Net.GuestIP.String()
		s.State.Netmask = opts.Net.Netmask
		s.State.HostMAC = opts.Net.HostMAC
		s.State.ProxyPort = opts.Net.ProxyPort
		s.State.Allow = opts.Allow
	}
	if err := s.api.loadSnapshot(load); err != nil {
		_ = s.Shutdown(2 * time.Second)
		return nil, 0, err
	}

	// A snapshot with a workspace needs its own copy of that disk, or every
	// restore would write into the same file and the "independent fork" claim
	// would be false in the most damaging possible way (P3-2).
	if metaErr == nil && meta.HasWorkspace {
		// Outside the run directory, which cleanup() deletes when the machine
		// stops — the same place `kelyfos run` puts a packed workspace, and for
		// the reason a resume just found: the image has to outlive the guest
		// that was using it, because writing it back to the host is something
		// that can only be done after the guest has stopped and flushed. The
		// caller owns removing it (E5-1).
		if s.State.Jailed {
			// Already done, and it had to be: the copy went into the jail
			// before the load, because the load is what needs the file to
			// exist. It is this machine's own copy at the name the snapshot
			// records, so there is nothing left to repoint — and repointing it
			// at a host path would name a file the jailed VMM cannot open
			// (P5-9).
			s.State.Workspace = filepath.Join(s.State.RunDir, defaultJailNames().Workspace)
		} else {
			mine := filepath.Join(Root(), "workspaces", id+".ext4")
			if err := os.MkdirAll(filepath.Dir(mine), 0o700); err != nil {
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, err
			}
			if err := copyFile(snapshotWorkspace(snapDir), mine); err != nil {
				copyWorkspaceManifest(snapshotWorkspace(snapDir), mine)
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("copy workspace for this fork: %w", err)
			}
			if err := s.api.patchDrive("workspace", mine); err != nil {
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("repoint workspace drive: %w", err)
			}
			s.State.Workspace = mine
		}
	}
	if err := s.api.resume(); err != nil {
		_ = s.Shutdown(2 * time.Second)
		return nil, 0, err
	}
	// The clock and entropy fix-up is a round trip to the guest, so completing
	// it is also the proof that the restored machine is answering. Measuring
	// through it makes "restore" mean the same thing "boot-to-ready" does —
	// stopping at resume() would time a machine that is running but not yet
	// known to be usable, which is the flattering number rather than the true
	// one.
	if err := s.Resync(); err != nil {
		_ = s.Shutdown(2 * time.Second)
		return nil, 0, err
	}
	elapsed := time.Since(started)
	s.State.BootReadyMS = elapsed.Milliseconds()
	// The restored machine gets the same check a booted one does, for the same
	// reason: a snapshot is loaded into a fresh Firecracker process, and that
	// process's filter is as much a fact about this run as the original's was
	// about that one (P5-2). confirmSeccomp writes the state itself.
	if err := s.confirmSeccomp(); err != nil {
		_ = s.Shutdown(2 * time.Second)
		return nil, 0, err
	}
	// A restored machine is the machine that was snapshotted, and restoring it
	// does not upgrade it. One taken before v0.9 has a supervisor that confines
	// nothing it spawns, and the host cannot fix that from out here — so it says
	// so, every restore, rather than letting the absence pass unremarked.
	//
	// Not a refusal, deliberately (D32): the jailer, the VMM's own filter, the
	// egress policy and the cgroup are all unchanged by the age of a snapshot,
	// and guest confinement is depth behind a boundary that still holds.
	// Refusing would make old snapshots unusable to buy nothing.
	//
	// Printed here rather than by each of the five commands that restore, for
	// the reason requireJail lives in New: a warning five call sites have to
	// remember is one that four of them will.
	if w := postureWarning(fromSnapshot, s.State.Profile, s.profileError); w != "" {
		warnf("%s", w)
	}
	return s, elapsed, nil
}

// Wait blocks until Firecracker exits.
func (s *Sandbox) Wait() error { <-s.done; return s.waitErr }

// ShutdownNote reports why the shutdown handshake could not confirm the
// workspace flush, or nil when it was confirmed (ST-5.3 review, finding 3).
// The write-back consults this before claiming success.
func (s *Sandbox) ShutdownNote() error { return s.shutdownRefused }

// Shutdown stops the microVM and removes everything it created. It is safe to
// call more than once.
//
// It asks first and insists afterwards: a shutdown RPC on the control channel
// lets the guest stop its children, flush its filesystems and power the machine
// off itself (docs/protocol.md §5.4). Only if that does not land does this fall
// back to signalling Firecracker — SIGTERM, then SIGKILL. Killing the VMM
// outright is a power cut, and a sandbox that is always power-cut can never
// promise a workspace was written back cleanly (P3-10).
func (s *Sandbox) Shutdown(grace time.Duration) error {
	if s.cmd != nil && s.cmd.Process != nil {
		select {
		case <-s.done:
		default:
			if err := s.requestShutdown(grace); err == nil {
				break
			}
			// The handshake did not land cleanly — including the guest
			// REFUSING shutdown because its workspace flush failed. The
			// fallback below must still stop the machine, but the flush
			// guarantee is void from here: record it, so the write-back can
			// refuse to pretend (ST-5.3 review, finding 3).
			s.shutdownRefused = fmt.Errorf("the shutdown handshake did not confirm the workspace flush")
			// The VMM, not our child: under the jailer our child is sudo, and
			// signalling sudo asks it to pass one on rather than ending the
			// machine. Falls back to the child when there is no separate VMM
			// pid, which is the unjailed case.
			s.signalVMM(syscall.SIGTERM)
			select {
			case <-s.done:
			case <-time.After(grace):
				s.signalVMM(syscall.SIGKILL)
				select {
				case <-s.done:
				case <-time.After(grace):
					_ = s.cmd.Process.Kill()
					<-s.done
				}
			}
		}
	}
	// The workspace comes out of the jail while there is still a jail to take it
	// out of, and after the guest has stopped, which is the only moment both are
	// true. On every ordinary installation the image inside the chroot is the
	// host's image under a second name — stageJail hard-links it, and the two
	// live under one cache root — so this costs two stats and does nothing.
	// Where the link could not be made, they are two files, the guest wrote to
	// the one inside, and cleanup below is about to delete it: that is the
	// silent total loss syncJailedWorkspace was written for, and it had no
	// caller at all (D-1).
	var syncErr error
	if s.State.Jailed && s.State.Workspace != "" {
		syncErr = syncJailedWorkspace(s.State.RunDir, s.State.Workspace)
	}

	// A restored jailed machine's workspace image lives INSIDE the run
	// directory, and cleanup() below is about to delete it (P6-27).
	//
	// Restore has to put it there: the jailed VMM can only open a path inside
	// its own chroot, and the snapshot names the file it was saved with. But the
	// caller writes the workspace back to the host AFTER Shutdown returns —
	// `kelyfos resume` registers that as a defer, and a defer registered first
	// runs last — so by the time anything reads the image, the directory holding
	// it is gone. What made this the worst kind of defect rather than a failed
	// sync is that the sync did not fail: it produced an empty tree, renamed the
	// person's project directory away, put the empty one in its place, and
	// printed "workspace written back". The agent's work was in neither, because
	// `.kelyfos-previous` holds what was there BEFORE the run.
	//
	// So the image is lifted somewhere that outlives the jail, at the one moment
	// both are true — the guest has stopped, and the jail is still here. This is
	// the same directory and the same name the unjailed restore branch already
	// uses, and the caller already removes it when the sync is done.
	if s.State.Jailed && s.State.Workspace != "" && withinDir(s.State.Workspace, s.State.RunDir) {
		kept := filepath.Join(Root(), "workspaces", s.State.ID+".ext4")
		if err := os.MkdirAll(filepath.Dir(kept), 0o700); err == nil {
			moved := os.Rename(s.State.Workspace, kept)
			copyWorkspaceManifest(s.State.Workspace, kept)
			if moved != nil {
				// A rename across devices fails; the copy is the fallback, and
				// it is the same fallback stageJail makes for the same reason.
				moved = copyFile(s.State.Workspace, kept)
			}
			if moved == nil {
				s.State.Workspace = kept
			} else if syncErr == nil {
				syncErr = fmt.Errorf("lift the workspace out of the jail: %w", moved)
			}
		}
	}
	s.closeListeners()
	s.opts.Net.Down()
	s.cleanup()
	if syncErr != nil {
		// Reported rather than swallowed. Every other error here is a machine
		// that was already stopping; this one is an agent's work not making it
		// back out, and a teardown that returns nil anyway is exactly how it
		// would go unnoticed.
		return fmt.Errorf("write the workspace back out of the jail: %w", syncErr)
	}
	if s.waitErr != nil {
		// A VM killed on purpose is not a failure worth reporting upward.
		var ee *exec.ExitError
		if errors.As(s.waitErr, &ee) {
			return nil
		}
	}
	return nil
}

// requestShutdown asks the guest to power itself off and waits for the VM to
// exit. An error means the guest could not be asked, or did not go.
func (s *Sandbox) requestShutdown(grace time.Duration) error {
	conn, err := Connect(s.State.UDSPath, proto.PortControl, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := proto.NewWriter(conn).Write(proto.ControlRequest{
		V: proto.Version, ID: "shutdown", Op: proto.OpShutdown,
	}); err != nil {
		return err
	}
	// The read deadline IS the grace: the guest answers only after its
	// workspace flush (syncfs) completes, and the flush is the thing this
	// grace exists to wait for. A fixed short deadline here would kill the
	// VMM mid-syncfs on a slow disk — the IA-H1 race re-entering through the
	// fix itself (ST-5.3 review, finding 2).
	deadline := grace
	if deadline <= 0 {
		deadline = 2 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	var resp proto.ControlResponse
	if err := proto.NewReader(conn).Read(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("guest refused shutdown: %v", resp.Error)
	}
	select {
	case <-s.done:
		return nil
	case <-time.After(grace):
		return fmt.Errorf("guest acknowledged shutdown but the microVM is still running")
	}
}

// RunDirOf is where a sandbox's run directory is, from its id alone. The
// marker below lives there, and the process that has to read it may not be the
// one holding the Sandbox.
func RunDirOf(id string) string { return jailRunDir(id) }

// PauseMarker is where a pause records that this machine's stop is a pause.
//
// It exists because the process that stops a sandbox and the process that owns
// it are not the same one: `kelyfos pause` asks the guest to power off, and the
// `kelyfos run` holding it wakes up and tears down — including writing the
// workspace back to the host, which is exactly what a pause must not do
// (docs/qol.md §1.3). The marker is how the owner learns which kind of stop
// this was, and it names the session so the message can say where the files
// went instead.
//
// Beside the state file rather than inside the chroot, and for the same reason
// (F19): a VMM that could plant one would make the run holding it skip its
// sync-back for ever, and print that the workspace travelled with a session
// nothing ever stored.
func PauseMarker(st *State) string { return filepath.Join(stateDir(st.RunDir), "paused") }

// PausedAs reports the name a pause stored this machine under, or "" if the
// stop was not a pause. Read rather than signalled, because the run directory is
// the one thing both processes already agree on.
func PausedAs(st *State) string {
	blob, err := os.ReadFile(PauseMarker(st))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(blob))
}

// RequestShutdown asks a running guest to power itself off, from a process that
// does not own it.
//
// The owner's Shutdown does this and more — it also closes listeners and takes
// down the network, which only the owner can do. This is the part a second
// process can do: ask, and wait for the machine to go.
func RequestShutdown(st *State, grace time.Duration) error {
	conn, err := Connect(st.UDSPath, proto.PortControl, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := proto.NewWriter(conn).Write(proto.ControlRequest{
		V: proto.Version, ID: "shutdown", Op: proto.OpShutdown,
	}); err != nil {
		return err
	}
	readDeadline := grace
	if readDeadline <= 0 {
		readDeadline = 2 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(readDeadline))
	var resp proto.ControlResponse
	if err := proto.NewReader(conn).Read(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("guest refused shutdown: %v", resp.Error)
	}
	// Waited for by watching the VM process rather than a channel this process
	// does not have. The owner is the one holding the wait; this one only needs
	// to know the machine is gone.
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(st.PID, 0); err != nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("guest acknowledged shutdown but the microVM (pid %d) is still running", st.PID)
}

// signalVMM sends a signal to the Firecracker process itself.
func (s *Sandbox) signalVMM(sig syscall.Signal) {
	if s.State.PID > 0 && s.cmd != nil && s.cmd.Process != nil && s.State.PID != s.cmd.Process.Pid {
		if p, err := os.FindProcess(s.State.PID); err == nil {
			_ = p.Signal(sig)
		}
		// The wrapper too, so it does not outlive the machine it started.
		_ = s.cmd.Process.Signal(sig)
		return
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(sig)
	}
}

// closeListeners closes the three sockets the guest dials in on, and the accept
// loops sitting on them return as a consequence.
//
// Called from cleanup rather than only from Shutdown, because Shutdown is not
// the only way a sandbox ends. New and Restore both bind these before there is a
// VMM to talk to, and both call cleanup on every failure after that point —
// which removed the run directory, unlinking the socket names without closing a
// single descriptor. A machine that failed to start therefore left up to three
// bound sockets and three goroutines blocked in Accept, held alive for the life
// of the process by the closure over s. On `kelyfos run` that process exits a
// moment later and nobody notices; inside `serve-mcp` or a team host it does
// not, and every failed boot cost three more (L-7).
//
// Safe to call more than once, which it is: Close on an already-closed listener
// returns an error nobody needs, and Shutdown calls this itself before cleanup
// so that the sockets go before the network they are reachable over.
func (s *Sandbox) closeListeners() {
	if s.readyLn != nil {
		_ = s.readyLn.Close()
	}
	if s.eventsLn != nil {
		_ = s.eventsLn.Close()
	}
	if s.teamLn != nil {
		_ = s.teamLn.Close()
	}
}

func (s *Sandbox) cleanup() {
	s.closeListeners()
	s.stopVMMWatchdog()
	if s.State.RunDir == "" {
		return
	}
	// The level above the chroot, so nothing of the jail is left behind — and
	// through sudo when a plain remove cannot finish, because the jailer leaves
	// root-owned files inside it (jail.go).
	_ = removeJail(filepath.Dir(s.State.RunDir))
}

// stateDir is where the host keeps its own record of a sandbox: one level above
// the chroot (F19).
//
// The jailer chroots Firecracker into the run directory and drops it to the
// invoking uid — the same uid that owns this file, at 0600. So a file inside the
// run directory is a file a compromised VMM can rewrite, and a compromised VMM
// is the exact threat the jail exists for: docs/threat-model.md calls the jail
// "depth, not a boundary", and this was the one path that handed the host's own
// files back. Everything a later kelyfos process does with a sandbox starts by
// reading this file. pause copies WorkspaceHost into the stored session and the
// resume renames the guest's tree over that host directory; `snapshot save`
// copies the addressing into the snapshot the next guest boots from; exec and
// shell dial UDSPath.
//
// jailDir(id) is the level above the chroot, and a chrooted process cannot walk
// above its own root at all. Everything the VMM legitimately needs — the vsock
// socket, the API socket, config.json, the images — stays exactly where it was.
func stateDir(runDir string) string { return filepath.Dir(runDir) }

func (s *Sandbox) writeState() error {
	blob, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir(s.State.RunDir), stateFile), blob, 0o600)
}

// serveReady accepts the guest's ready channel and forwards the first ready
// frame. The guest reconnects after a drop, so this keeps accepting.
func (s *Sandbox) serveReady() {
	for {
		conn, err := s.readyLn.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			r := proto.NewReader(conn)
			for {
				var msg struct {
					proto.Ready
					UptimeMS int64 `json:"uptime_ms"`
				}
				if err := r.Read(&msg); err != nil {
					return
				}
				if msg.Type == "ready" {
					select {
					case s.ready <- msg.Ready:
					default:
					}
				}
			}
		}()
	}
}

func (s *Sandbox) drainConsole(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 256<<10)
	for sc.Scan() {
		if s.opts.Console != nil {
			fmt.Fprintln(s.opts.Console, sc.Text())
		}
	}
}

// RunningSessions is the set of flight-recorder session ids with a live
// sandbox writing into them right now — every currently-alive sandbox's own
// RecordSession(), which is a team's or a serve-mcp process's session id for
// a member sandbox and the sandbox's own id otherwise.
//
// It exists for `kelyfos sessions erase`'s own guard (P7-5, D61, B1). A
// guard that only checks whether a run directory is named for the id being
// erased — RunDirOf(id) — sees an ordinary `kelyfos run` sandbox fine,
// because that sandbox's own id names its own run directory. It cannot see
// a running team: `host/team.go`'s raiseTeam opens the team's chain under a
// fresh sandbox.NewID() that is never any sandbox's own id, so no run
// directory is ever named for it, even while every member sandbox in the
// team is alive and writing into that exact chain. This answers the
// question RunDirOf(id) alone cannot: is ANY live sandbox's own
// RecordSession() this id, whichever sandbox actually holds the run
// directory.
func RunningSessions() (map[string]bool, error) {
	live := map[string]bool{}
	entries, err := os.ReadDir(filepath.Join(RunRoot(), "firecracker"))
	if err != nil {
		if os.IsNotExist(err) {
			return live, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := readState(RunDirOf(e.Name()))
		if err != nil {
			if os.IsNotExist(err) {
				continue // nothing has ever written a record here
			}
			// A record that exists and does not pass its checks is the one case
			// where "I cannot read this" must not collapse into "nothing is
			// running here". This answer is what `sessions erase` and `sessions
			// prune` use to decide a chain is safe to rewrite or delete, and the
			// empty answer is the unsafe one — a refused record is a reason to
			// leave a session alone, not a reason to treat it as gone.
			//
			// The id is what gets marked, because the id is the directory's own
			// name and does not come out of the file. A team member's Session
			// field does, and a record this host has just refused is not one to
			// take a chain id from — so a refused member of a live team protects
			// its own chain and not the team's, which is the honest limit of
			// what can be known here and is stated rather than papered over.
			live[e.Name()] = true
			continue
		}
		if !alive(st.PID) {
			continue
		}
		live[st.RecordSession()] = true
	}
	return live, nil
}

// Load reads the state of a running sandbox. With an empty id it finds the only
// running sandbox, and refuses to guess when there is more than one.
func Load(id string) (*State, error) {
	// `kelyfos run -- <cmd>` exports this so the command it launches reaches
	// the sandbox that launched it, even when others are running (D23).
	if id == "" {
		id = os.Getenv("KELYFOS_SANDBOX")
	}
	if id != "" {
		return readState(RunDirOf(id))
	}
	// One level down from the run root: the layout is the jailer's,
	// <run>/firecracker/<id>/root, because the run directory is the chroot
	// (P5-1). Listing looks where the ids are rather than where they used to be.
	entries, err := os.ReadDir(filepath.Join(RunRoot(), "firecracker"))
	if err != nil {
		return nil, fmt.Errorf("no running sandbox (nothing under %s)", RunRoot())
	}
	var found []*State
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := readState(RunDirOf(e.Name()))
		if err != nil || !alive(st.PID) {
			continue
		}
		found = append(found, st)
	}
	switch len(found) {
	case 0:
		return nil, errors.New("no running sandbox — start one with `kelyfos run`")
	case 1:
		return found[0], nil
	default:
		ids := make([]string, 0, len(found))
		for _, st := range found {
			ids = append(ids, st.ID)
		}
		return nil, fmt.Errorf("%d sandboxes are running; pick one with --sandbox: %v", len(found), ids)
	}
}

func readState(runDir string) (*State, error) {
	dir := stateDir(runDir)
	blob, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, fmt.Errorf("corrupt sandbox state in %s: %w", dir, err)
	}
	if err := st.validate(runDir); err != nil {
		return nil, err
	}
	return &st, nil
}

// validate is what a state file has to survive before anything acts on it.
//
// stateDir is what closes F19 — a chrooted process cannot reach a file above its
// own root — and this is the half that does not depend on that being true.
// `--no-jail` exists, another process running as this user is not the VMM but is
// not the host either, and a defence that is only correct while one other
// defence holds is the shape most of this review's findings had. So every field
// a later process turns into a host action is checked against something this
// process can work out for itself.
//
// The rule throughout is derivation, not plausibility: the id names its own
// directory, the run directory is the one the id produces, the sockets are
// inside it, the images are under the cache root, and the addressing is a /30
// this package derives. A value that could not have come from here is refused
// with a message rather than obeyed, which is the difference between a file
// being data and a file being an instruction.
func (st *State) validate(runDir string) error {
	dir := stateDir(runDir)
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%s in %s is not a state this host will act on: %s",
			stateFile, dir, fmt.Sprintf(format, args...))
	}
	if id := filepath.Base(dir); st.ID != id {
		return bad("it is the record of sandbox %q and it is stored under %q", st.ID, id)
	}
	if filepath.Clean(st.RunDir) != filepath.Clean(runDir) {
		return bad("its run directory is %q, and sandbox %s's is %q", st.RunDir, st.ID, runDir)
	}
	// The channels a second process dials, and the API socket `snapshot save`
	// and `pause` drive the VMM through. Both are created inside the run
	// directory by New, so both are inside it here.
	for _, f := range []struct{ name, path string }{
		{"uds_path", st.UDSPath},
		{"api_path", st.APIPath},
	} {
		if f.path != "" && !withinDir(f.path, runDir) {
			return bad("its %s is %q, which is outside the sandbox's own directory", f.name, f.path)
		}
	}
	// The two block devices. `snapshot save` copies the workspace into the
	// snapshot the next guest boots from, and the plugins device is packed into
	// the guest read-only; every path either can legitimately hold is one this
	// tool built under its own cache root.
	for _, f := range []struct{ name, path string }{
		{"workspace", st.Workspace},
		{"plugins", st.Plugins},
	} {
		if f.path != "" && !withinDir(f.path, Root()) {
			return bad("its %s image is %q, which is outside %s", f.name, f.path, Root())
		}
	}
	if st.CGroupPath != "" && !withinDir(st.CGroupPath, "/sys/fs/cgroup") {
		return bad("its cgroup is %q, which is not under /sys/fs/cgroup", st.CGroupPath)
	}
	// The pid, for the same reason the interface name is checked: alive() sends
	// it a signal and Sample() reads /proc/<pid>/io from it, so a rewritten one
	// makes a dead sandbox look alive — which is what `sessions erase` asks
	// before deciding a chain is safe to rewrite — or files another process's
	// counters under this machine's name.
	//
	// The jailer's own firecracker.pid is compared against where it exists.
	// **It is a consistency check and not a trust anchor**, and the difference
	// is worth stating because the first version of this comment got it wrong.
	// It said the file is written by root at mode 0644, so the VMM — dropped to
	// the invoking uid — can read it and cannot rewrite it. The first half is
	// observed and true; the conclusion is false, because unlink(2) is governed
	// by write permission on the *directory*, and the directory is the chroot
	// the VMM owns. Measured:
	//
	//	dir   <invoking uid> 700      file  root:root 644
	//	in-place write -> Permission denied
	//	unlink         -> SUCCEEDED
	//	recreate       -> SUCCEEDED, content=99
	//
	// So anyone who can rewrite sandbox.json can rewrite this too, and after
	// F19 neither is reachable from inside the chroot anyway. What the check is
	// worth is catching a stale or truncated record — a real failure mode — at
	// no cost. Absent or unreadable is not an error: --no-jail writes none, and
	// a half-torn-down directory may have lost it.
	if st.PID < 0 {
		return bad("its pid is %d", st.PID)
	}
	if blob, err := os.ReadFile(filepath.Join(runDir, "firecracker.pid")); err == nil {
		if jailed, convErr := strconv.Atoi(strings.TrimSpace(string(blob))); convErr == nil &&
			jailed > 0 && st.PID != 0 && st.PID != jailed {
			return bad("it names pid %d and the jailer recorded %d for this machine", st.PID, jailed)
		}
	}
	// WorkspaceHost is the one path here that is genuinely the person's own and
	// so cannot be derived. What can be said about it is said: a resume renames
	// the guest's tree over this directory, so it has to be an absolute, clean
	// path, and it is not allowed to be anywhere inside this tool's own cache —
	// kelyfos's state is not somebody's project.
	if p := st.WorkspaceHost; p != "" {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return bad("its workspace_host is %q, which is not an absolute, clean path", p)
		}
		if r := filepath.Clean(Root()); p == r || withinDir(p, r) {
			return bad("its workspace_host is %q, inside %s — a resume renames the guest's tree "+
				"over that directory, and kelyfos's own state is not a project", p, r)
		}
	}
	return st.validateNetwork(bad)
}

// tapName is the interface a sandbox id produces.
//
// It mirrors the derivation newNetwork and newNetworkAt each do inline, and it
// is written out a third time here rather than shared because network.go is
// mid-merge in another workstream. That is a drift risk and is recorded as one:
// the two constructors should call this. The bound is IFNAMSIZ-1, and for a real
// id — eight hex characters — nothing is ever cut.
func tapName(id string) string {
	tap := "kelyfos" + id
	if len(tap) > 15 {
		tap = tap[:15]
	}
	return tap
}

// validateNetwork checks the addressing, which the review's list did not
// include and which is where this file reaches furthest.
//
// F9 gives the egress proxy a Peer address and refuses a connection from
// anywhere else. On the restore path that address comes from here: SnapshotRunning
// copies HostIP/GuestIP/Netmask/HostMAC/ProxyPort out of this file into the
// snapshot's meta.json, and host/snapshot.go's restoreNetwork feeds them back
// through NewNetworkFor into newNetworkAt. A compromised VMM cannot write a
// *malformed* address — up() refuses that — but it can write a valid and wrong
// one, and 127.0.0.1 is the one that matters: it is an address any local process
// can source from, so the peer check would pass for the wrong peer and only the
// nftables layer would still be refusing. The proxy binds on HostIP too, so a
// loopback host address makes the proxy — with the operator's credentials
// attached — reachable by every process on the machine, which is the whole of F9
// re-opened through a file.
//
// So the pair is checked against deriveAddrs' own arithmetic rather than merely
// parsed: link-local, a /30, host at .1 and guest at .2 of it, and not the /30
// holding the cloud metadata address, which deriveAddrs itself refuses.
func (st *State) validateNetwork(bad func(string, ...any) error) error {
	if st.HostIP == "" && st.GuestIP == "" {
		// A sandbox with no allowlist has no NIC at all — not a firewalled one,
		// not an empty allowlist, none (docs/networking.md §1). New writes the
		// six network fields together or writes none of them, so half of them is
		// not a state this package produces.
		if st.TAP != "" {
			return bad("it names the interface %q and no addressing at all; a sandbox's network "+
				"is recorded whole or not at all", st.TAP)
		}
		return nil
	}
	host, guest := net.ParseIP(st.HostIP).To4(), net.ParseIP(st.GuestIP).To4()
	if host == nil || guest == nil {
		return bad("its addressing is unusable (host %q, guest %q)", st.HostIP, st.GuestIP)
	}
	if host[0] != 169 || host[1] != 254 {
		return bad("its host address %s is outside the link-local range every sandbox address "+
			"is derived from", host)
	}
	if !sameSlash30(host, guest) || host[3]&0x03 != 1 || guest[3] != host[3]+1 {
		return bad("host %s and guest %s are not the two halves of a /30 this host derives", host, guest)
	}
	if sameSlash30(host, metadataIP) {
		return bad("its /30 holds the cloud metadata address %s, which no sandbox is given", metadataIP)
	}
	if st.Netmask != "" && st.Netmask != "255.255.255.252" {
		// It becomes the guest's own `ip=` boot argument, so it is what the
		// guest treats as on-link. Every sandbox gets a /30.
		return bad("its netmask is %q and every sandbox is a /30", st.Netmask)
	}
	if st.TAP != "" && st.TAP != tapName(st.ID) {
		// Derivable, so nothing else is legitimate. Read back as a path under
		// /sys/class/net to sample this machine's byte counters, so a rewritten
		// one puts another interface's traffic in the flight recorder under
		// this sandbox's name.
		return bad("its interface is %q and sandbox %s's is %q", st.TAP, st.ID, tapName(st.ID))
	}
	if st.HostMAC != "" {
		// Not bound to the id: a restore deliberately keeps the address the
		// snapshot was taken with, so the guest's ARP entry still matches (D22).
		// What is checked is the class — unicast and locally administered, which
		// is all hostMAC ever mints — because this is the argument to
		// `ip link set … address`.
		mac, err := net.ParseMAC(st.HostMAC)
		if err != nil || len(mac) != 6 {
			return bad("its host MAC %q is not an address", st.HostMAC)
		}
		if mac[0]&0x01 != 0 || mac[0]&0x02 == 0 {
			return bad("its host MAC %s is not a locally administered unicast address", mac)
		}
	}
	if st.ProxyPort < 0 || st.ProxyPort > 65535 {
		return bad("its proxy port is %d", st.ProxyPort)
	}
	return nil
}

func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// NewNetwork brings up this sandbox's TAP before the proxy binds on it. The
// caller then binds the proxy, calls Restrict with the port, and passes the
// Network to New.
func NewNetwork(sandboxID string) (*Network, error) {
	if err := CheckPrivileges(); err != nil {
		return nil, err
	}
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	return newNetwork(sandboxID, u.Username)
}

// NewNetworkFor re-creates the network a snapshot was taken with, so a restored
// guest finds the proxy at the address it already believes in (D22).
func NewNetworkFor(sandboxID, hostIP, guestIP, netmask, hostMAC string) (*Network, error) {
	if err := CheckPrivileges(); err != nil {
		return nil, err
	}
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	return newNetworkAt(sandboxID, u.Username, hostIP, guestIP, netmask, hostMAC)
}

// NewID mints a sandbox id. Exposed because the network has to exist before the
// sandbox that uses it.
func NewID() (string, error) { return newID() }

// guestMAC derives a stable locally-administered MAC from the sandbox id, so a
// guest keeps the same address across restarts of the same sandbox and two
// sandboxes never collide.
func guestMAC(id string) string {
	b, err := hex.DecodeString(id)
	if err != nil || len(b) < 4 {
		return "02:00:00:00:00:01"
	}
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3])
}

func newID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate sandbox id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// withinDir reports whether path is inside dir.
//
// Lexical rather than a stat, because it is asked about a path that is about to
// be deleted and the answer must not depend on the file still being there.
func withinDir(path, dir string) bool {
	if dir == "" {
		return false
	}
	p, d := filepath.Clean(path), filepath.Clean(dir)
	return p != d && strings.HasPrefix(p, d+string(os.PathSeparator))
}
