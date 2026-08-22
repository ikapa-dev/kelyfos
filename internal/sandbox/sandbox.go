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
	"strings"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
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
	// OnGuestEvent receives what the guest reports on the events channel
	// (docs/protocol.md §5.5). The caller decides what to record; the guest
	// never writes the flight recorder itself (docs/events.md §1).
	OnGuestEvent func(proto.GuestEvent)
}

// State is the on-disk description of a running sandbox, written into the run
// directory so a second process — `kelyfos exec` — can find the channels
// without being told where they are.
type State struct {
	ID          string    `json:"id"`
	PID         int       `json:"pid"`
	Arch        string    `json:"arch"`
	Flavor      string    `json:"flavor"`
	UDSPath     string    `json:"uds_path"`
	APIPath     string    `json:"api_path"`
	TAP         string    `json:"tap,omitempty"`
	HostIP      string    `json:"host_ip,omitempty"`
	GuestIP     string    `json:"guest_ip,omitempty"`
	Netmask     string    `json:"netmask,omitempty"`
	HostMAC     string    `json:"host_mac,omitempty"`
	ProxyPort   int       `json:"proxy_port,omitempty"`
	VcpuCount   int       `json:"vcpu_count,omitempty"`
	MemMiB      int       `json:"mem_mib,omitempty"`
	CPUQuota    int       `json:"cpu_quota_percent,omitempty"`
	CGroupPath  string    `json:"cgroup_path,omitempty"`
	ScratchByte int64     `json:"scratch_bytes,omitempty"`
	NetMbpsRx   int       `json:"net_mbps_rx,omitempty"`
	NetMbpsTx   int       `json:"net_mbps_tx,omitempty"`
	DiskIOPS    int       `json:"disk_iops,omitempty"`
	DiskMbps    int       `json:"disk_mbps,omitempty"`
	Workspace   string    `json:"workspace,omitempty"`
	Allow       []string  `json:"allow,omitempty"`
	RunDir      string    `json:"run_dir"`
	StartedAt   time.Time `json:"started_at"`
	BootReadyMS int64     `json:"boot_ready_ms"`
}

// Sandbox is a running microVM.
type Sandbox struct {
	State    State
	api      *api
	opts     Options
	cmd      *exec.Cmd
	readyLn  net.Listener
	eventsLn net.Listener
	ready    chan proto.Ready
	done     chan struct{}
	waitErr  error
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

	id := opts.ID
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return nil, err
		}
	}
	runDir := filepath.Join(RunRoot(), id)
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
	}
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
	s.api = newAPI(s.State.APIPath)

	return s, nil
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
	go s.serveEvents()
	return nil
}

// serveEvents reads guest-reported events and hands them to the caller. The
// guest reconnects after a drop, so this keeps accepting; nothing here trusts
// the frames beyond their shape, because the guest runs untrusted code and this
// is a report, not a record.
func (s *Sandbox) serveEvents() {
	for {
		conn, err := s.eventsLn.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			r := proto.NewReader(conn)
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
	// Under systemd this prefixes the command with the scope request; on the
	// direct path it is unchanged (F-D11).
	argv = s.opts.CPUSlice.WrapArgv(argv)
	cmd := exec.Command(argv[0], argv[1:]...)
	// Its own process group, so a Ctrl-C delivered to the whole foreground
	// group does not race our orderly shutdown.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// On the direct path, place it in its cgroup at clone time rather than
	// moving it once it is already running: a quota that starts a moment late
	// is a quota with a hole in it (E1-2).
	if s.opts.CPUSlice.Direct() {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = s.opts.CPUSlice.FD()
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
	s.State.PID = cmd.Process.Pid
	go s.drainConsole(stdout)
	go func() {
		s.waitErr = cmd.Wait()
		close(s.done)
	}()
	// Read the quota back rather than trusting that asking for it worked.
	if s.opts.CPUSlice != nil {
		if err := s.opts.CPUSlice.Confirm(cmd.Process.Pid); err != nil {
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
		return r, s.writeState()
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

	if err := s.api.pause(); err != nil {
		return "", "", err
	}
	if err := s.api.createSnapshot(statePath, memPath); err != nil {
		// Leave the machine running rather than paused: a failed snapshot
		// should cost a snapshot, not the session.
		_ = s.api.resume()
		return "", "", err
	}
	if err := s.api.resume(); err != nil {
		return "", "", err
	}
	return statePath, memPath, nil
}

// SnapshotRunning snapshots a sandbox this process did not start, by talking to
// its API socket directly. `kelyfos snapshot save` is a separate invocation from
// the `kelyfos run` holding the machine open, so it has no Sandbox to call.
// SnapshotMeta travels with a snapshot so a later restore knows what the machine
// was, rather than making the caller remember.
type SnapshotMeta struct {
	Arch         string `json:"arch"`
	Flavor       string `json:"flavor"`
	HasWorkspace bool   `json:"has_workspace"`
	// WorkspacePath is where the workspace disk lived when the snapshot was
	// taken. It has to be recorded because Firecracker insists that a block
	// device's backing file exists at its original path before a snapshot will
	// load at all — the drive can only be repointed afterwards.
	WorkspacePath string `json:"workspace_path,omitempty"`
	WorkspaceSize int64  `json:"workspace_size,omitempty"`
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
}

func snapshotMetaPath(dir string) string  { return filepath.Join(dir, "meta.json") }
func snapshotWorkspace(dir string) string { return filepath.Join(dir, "workspace.ext4") }

// ReadSnapshotMeta loads what was recorded alongside a snapshot.
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

	a := newAPI(st.APIPath)
	if err := a.pause(); err != nil {
		return "", "", err
	}
	if err := a.createSnapshot(statePath, memPath); err != nil {
		_ = a.resume()
		return "", "", err
	}

	meta := SnapshotMeta{Arch: st.Arch, Flavor: st.Flavor}
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
	if st.Workspace != "" {
		// The workspace disk is part of the machine's state, so it travels with
		// the snapshot. Copying it while the VM is paused is what makes the copy
		// consistent with the memory image.
		if err := copyFile(st.Workspace, snapshotWorkspace(dir)); err != nil {
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

	id := opts.ID
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return nil, 0, err
		}
	}
	runDir := filepath.Join(RunRoot(), id)
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
			RunDir:  runDir, StartedAt: time.Now(),
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
	s.api = newAPI(s.State.APIPath)

	started := time.Now()
	cmd := exec.Command("firecracker", "--api-sock", s.State.APIPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	s.State.PID = cmd.Process.Pid
	go s.drainConsole(stdout)
	go func() { s.waitErr = cmd.Wait(); close(s.done) }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.api.waitReady(ctx); err != nil {
		_ = s.Shutdown(2 * time.Second)
		return nil, 0, err
	}
	// Firecracker will not load a snapshot unless every block device's backing
	// file is present at the path recorded in it — the drive can only be
	// repointed after the load succeeds. So the captured workspace is put back
	// where it was first, purely so the load has something to open; each fork
	// then swaps in its own copy before the machine is resumed, and no guest
	// I/O happens in between.
	meta, metaErr := ReadSnapshotMeta(snapDir)
	if metaErr == nil && meta.HasWorkspace && meta.WorkspacePath != "" {
		if _, err := os.Stat(meta.WorkspacePath); os.IsNotExist(err) {
			if err := copyFile(snapshotWorkspace(snapDir), meta.WorkspacePath); err != nil {
				_ = s.Shutdown(2 * time.Second)
				return nil, 0, fmt.Errorf("stage workspace for snapshot load: %w", err)
			}
		}
	}

	// A machine frozen with a NIC cannot be loaded until that NIC has somewhere
	// to attach. The TAP it was taken with is long gone, so it is re-paired to
	// the one this restore just created (D22).
	load := snapshotLoad{
		SnapshotPath:  statePath,
		MemBackend:    memBackend{BackendPath: memPath, BackendType: "File"},
		ResumeVM:      false,
		VsockOverride: &vsockOverride{UDSPath: s.State.UDSPath},
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
		mine := filepath.Join(runDir, "workspace.ext4")
		if err := copyFile(snapshotWorkspace(snapDir), mine); err != nil {
			_ = s.Shutdown(2 * time.Second)
			return nil, 0, fmt.Errorf("copy workspace for this fork: %w", err)
		}
		if err := s.api.patchDrive("workspace", mine); err != nil {
			_ = s.Shutdown(2 * time.Second)
			return nil, 0, fmt.Errorf("repoint workspace drive: %w", err)
		}
		s.State.Workspace = mine
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
	return s, elapsed, s.writeState()
}

// Wait blocks until Firecracker exits.
func (s *Sandbox) Wait() error { <-s.done; return s.waitErr }

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
			_ = s.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-s.done:
			case <-time.After(grace):
				_ = s.cmd.Process.Kill()
				<-s.done
			}
		}
	}
	if s.readyLn != nil {
		_ = s.readyLn.Close()
	}
	if s.eventsLn != nil {
		_ = s.eventsLn.Close()
	}
	s.opts.Net.Down()
	s.cleanup()
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
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
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

func (s *Sandbox) cleanup() {
	if s.State.RunDir != "" {
		_ = os.RemoveAll(s.State.RunDir)
	}
}

func (s *Sandbox) writeState() error {
	blob, err := json.MarshalIndent(s.State, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.State.RunDir, stateFile), blob, 0o600)
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

// Load reads the state of a running sandbox. With an empty id it finds the only
// running sandbox, and refuses to guess when there is more than one.
func Load(id string) (*State, error) {
	// `kelyfos run -- <cmd>` exports this so the command it launches reaches
	// the sandbox that launched it, even when others are running (D23).
	if id == "" {
		id = os.Getenv("KELYFOS_SANDBOX")
	}
	if id != "" {
		return readState(filepath.Join(RunRoot(), id))
	}
	entries, err := os.ReadDir(RunRoot())
	if err != nil {
		return nil, fmt.Errorf("no running sandbox (nothing under %s)", RunRoot())
	}
	var found []*State
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st, err := readState(filepath.Join(RunRoot(), e.Name()))
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

func readState(dir string) (*State, error) {
	blob, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, fmt.Errorf("corrupt sandbox state in %s: %w", dir, err)
	}
	return &st, nil
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
