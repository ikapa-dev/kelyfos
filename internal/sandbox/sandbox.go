// Package sandbox is the host side of a KelyfOS microVM: where its files live,
// how Firecracker is configured and launched, how the host-side channels are
// bound, and how it is torn down.
package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	Arch      string
	Flavor    string
	ImageDir  string
	VcpuCount int
	MemMiB    int
	Quiet     bool
	// Console, when set, receives the guest's serial output line by line.
	Console io.Writer
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
	RunDir      string    `json:"run_dir"`
	StartedAt   time.Time `json:"started_at"`
	BootReadyMS int64     `json:"boot_ready_ms"`
}

// Sandbox is a running microVM.
type Sandbox struct {
	State   State
	opts    Options
	cmd     *exec.Cmd
	readyLn net.Listener
	ready   chan proto.Ready
	done    chan struct{}
	waitErr error
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

	id, err := newID()
	if err != nil {
		return nil, err
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
			RunDir:    runDir,
			StartedAt: time.Now(),
		},
	}

	cfg := FirecrackerConfig{
		BootSource: BootSource{
			KernelImagePath: kernel,
			BootArgs:        bootArgs(opts.Arch, opts.Quiet),
		},
		Drives: []Drive{{
			DriveID:      "rootfs",
			PathOnHost:   rootfs,
			IsRootDevice: true,
			IsReadOnly:   true,
		}},
		MachineConfig: MachineConfig{VcpuCount: opts.VcpuCount, MemSizeMib: opts.MemMiB},
		Vsock:         &Vsock{GuestCID: proto.CIDGuest, UDSPath: s.State.UDSPath},
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

	return s, nil
}

// Start launches Firecracker and returns once the process is running. It does
// not wait for the guest — use WaitReady for that.
func (s *Sandbox) Start(ctx context.Context) error {
	cmd := exec.Command("firecracker", "--no-api",
		"--config-file", filepath.Join(s.State.RunDir, "config.json"))
	// Its own process group, so a Ctrl-C delivered to the whole foreground
	// group does not race our orderly shutdown.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

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

func newID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate sandbox id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
