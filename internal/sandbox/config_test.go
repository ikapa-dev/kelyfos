package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootArgsOmitRootAndReadOnly(t *testing.T) {
	// Firecracker inserts root= and ro itself from the drive flags; emitting
	// them here would put each option on the command line twice.
	for _, arch := range []string{"aarch64", "x86_64"} {
		args := bootArgs(arch, true, nil, false, 0, "", false)
		for _, forbidden := range []string{"root=", " ro ", "8250.nr_uarts"} {
			if strings.Contains(" "+args+" ", forbidden) {
				t.Errorf("%s boot args must not contain %q: %s", arch, forbidden, args)
			}
		}
		// PID 1 is the supervisor itself since P2-1 — there is no /init script.
		for _, required := range []string{"console=ttyS0", "init=/sbin/kelyfos-supervisor", "nomodule", "pci=off"} {
			if !strings.Contains(args, required) {
				t.Errorf("%s boot args missing %q: %s", arch, required, args)
			}
		}
	}
}

func TestI8042KnobsAreX86Only(t *testing.T) {
	if strings.Contains(bootArgs("aarch64", true, nil, false, 0, "", false), "i8042") {
		t.Error("aarch64 has no i8042 controller; the knobs must not be passed")
	}
	if !strings.Contains(bootArgs("x86_64", true, nil, false, 0, "", false), "i8042.noaux") {
		t.Error("x86_64 should pass the i8042 knobs to save boot time")
	}
}

func TestQuietIsOptional(t *testing.T) {
	if strings.Contains(bootArgs("aarch64", false, nil, false, 0, "", false), "quiet") {
		t.Error("verbose boot must not pass quiet")
	}
	if !strings.Contains(bootArgs("aarch64", true, nil, false, 0, "", false), "quiet") {
		t.Error("quiet boot must pass quiet")
	}
}

func TestKernelArtifactIsUncompressedPerArch(t *testing.T) {
	if a, _ := KernelArtifact("aarch64"); a != "Image" {
		t.Errorf("aarch64 must boot the uncompressed Image, got %q", a)
	}
	if a, _ := KernelArtifact("x86_64"); a != "vmlinux" {
		t.Errorf("x86_64 must boot the uncompressed ELF vmlinux, got %q", a)
	}
	if _, err := KernelArtifact("riscv64"); err == nil {
		t.Error("an unsupported architecture must be an error, not a guess")
	}
}

func TestNoNICMeansNoNetworkBootArgs(t *testing.T) {
	// With no allowlist there is no Network, and therefore nothing on the
	// command line that could configure an interface the machine does not have.
	args := bootArgs("aarch64", true, nil, false, 0, "", false)
	for _, forbidden := range []string{"ip=", "kelyfos.proxy="} {
		if strings.Contains(args, forbidden) {
			t.Errorf("a sandbox with no egress must not carry %q: %s", forbidden, args)
		}
	}
}

func TestNetworkBootArgsConfigureTheNIC(t *testing.T) {
	n := &Network{
		TAP:       "kelyfos00112233",
		HostIP:    net.IPv4(169, 254, 1, 1),
		GuestIP:   net.IPv4(169, 254, 1, 2),
		Netmask:   "255.255.255.252",
		ProxyPort: 41234,
	}
	args := bootArgs("aarch64", true, n, false, 0, "", false)
	for _, want := range []string{
		"ip=169.254.1.2::169.254.1.1:255.255.255.252::eth0:off",
		"kelyfos.proxy=169.254.1.1:41234",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("boot args missing %q: %s", want, args)
		}
	}
}

// The scratch cap reaches the guest on the kernel command line, because the
// overlay is mounted before any channel exists to ask over — and because the
// command line is the one thing in the guest the guest did not write.
func TestScratchCapRidesTheCommandLine(t *testing.T) {
	if got := bootArgs("aarch64", true, nil, false, 0, "", false); strings.Contains(got, "kelyfos.scratch") {
		t.Errorf("an uncapped sandbox still names a scratch size: %s", got)
	}
	got := bootArgs("aarch64", true, nil, true, 64<<20, "", false)
	if !strings.Contains(got, "kelyfos.scratch=67108864") {
		t.Errorf("the scratch cap is missing or not in bytes: %s", got)
	}
	// The workspace is a separate device and must still be announced.
	if !strings.Contains(got, "kelyfos.workspace=/dev/vdb") {
		t.Errorf("the workspace disappeared: %s", got)
	}
}

// A guest is told which agent it is on the kernel command line, so it cannot
// rename itself into another agent's edges.
func TestAgentNameRidesTheCommandLine(t *testing.T) {
	if got := bootArgs("x86_64", true, nil, false, 0, "", false); strings.Contains(got, "kelyfos.agent") {
		t.Errorf("a sandbox with no team still names an agent: %s", got)
	}
	got := bootArgs("x86_64", true, nil, false, 0, "worker-2", false)
	if !strings.Contains(got, "kelyfos.agent=worker-2") {
		t.Errorf("the agent name is missing: %s", got)
	}
}

// A spawn budget is the host's answer, and the guest is told it on the same
// channel as its own name — so the tool is listed only where it can work.
func TestSpawnPermissionRidesTheCommandLine(t *testing.T) {
	if got := bootArgs("aarch64", true, nil, false, 0, "master", false); strings.Contains(got, "kelyfos.spawn") {
		t.Errorf("an agent with no budget is told it may spawn: %s", got)
	}
	if got := bootArgs("aarch64", true, nil, false, 0, "master", true); !strings.Contains(got, "kelyfos.spawn=1") {
		t.Errorf("an agent with a budget is not told: %s", got)
	}
}

// A team member's events belong in the team's chain; everything else keeps its
// own. The fallback is what makes an older sandbox.json, written before the
// field existed, still load and still work (E2-7).
func TestRecordSessionFallsBackToTheSandboxID(t *testing.T) {
	if got := (State{ID: "abc"}).RecordSession(); got != "abc" {
		t.Errorf("a sandbox with no team recorded into %q, want its own id", got)
	}
	if got := (State{ID: "abc", Session: "team-1"}).RecordSession(); got != "team-1" {
		t.Errorf("a team member recorded into %q, want the team's session", got)
	}
}

// The field has to survive the round trip through sandbox.json, because the
// process that reads it back — `kelyfos exec` — is a different one from the
// process that wrote it.
func TestSessionSurvivesTheStateFile(t *testing.T) {
	dir := t.TempDir()
	s := &Sandbox{State: State{ID: "abc", Agent: "worker-1", Session: "team-1", RunDir: dir}}
	if err := s.writeState(); err != nil {
		t.Fatal(err)
	}
	back, err := readState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if back.Session != "team-1" || back.Agent != "worker-1" {
		t.Errorf("state came back as %+v", back)
	}
	// A file written before the field existed has no session and must load
	// with an empty one rather than failing.
	older := t.TempDir()
	if err := os.WriteFile(filepath.Join(older, stateFile),
		[]byte(`{"id":"xyz","run_dir":"/tmp"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, err := readState(older)
	if err != nil {
		t.Fatalf("a sandbox.json without a session field failed to load: %v", err)
	}
	if prev.Session != "" || prev.RecordSession() != "xyz" {
		t.Errorf("an older state file did not fall back: %+v", prev)
	}
}

// A snapshot is a memory image of a booted guest — the most sensitive file this
// program writes. Firecracker creates it with the process umask, so the mode is
// taken back explicitly rather than left to the directory above it.
func TestASnapshotIsNotReadableByAnyoneElse(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	mem := filepath.Join(dir, "memory")
	for _, p := range []string{state, mem} {
		if err := os.WriteFile(p, []byte("x"), 0o664); err != nil {
			t.Fatal(err)
		}
	}
	restrictSnapshot(state, mem)
	for _, p := range []string{state, mem} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s is mode %o, want 600", filepath.Base(p), mode)
		}
	}
	// A file that is not there is not an error: a snapshot that failed halfway
	// should report the failure, not a chmod complaint about its debris.
	restrictSnapshot(filepath.Join(dir, "absent"))
}
