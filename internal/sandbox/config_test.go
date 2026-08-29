package sandbox

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBootArgsOmitRootAndReadOnly(t *testing.T) {
	// Firecracker inserts root= and ro itself from the drive flags; emitting
	// them here would put each option on the command line twice.
	for _, arch := range []string{"aarch64", "x86_64"} {
		args := bootArgs(Options{Arch: arch, Quiet: true}, "")
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
	if strings.Contains(bootArgs(Options{Arch: "aarch64", Quiet: true}, ""), "i8042") {
		t.Error("aarch64 has no i8042 controller; the knobs must not be passed")
	}
	if !strings.Contains(bootArgs(Options{Arch: "x86_64", Quiet: true}, ""), "i8042.noaux") {
		t.Error("x86_64 should pass the i8042 knobs to save boot time")
	}
}

func TestQuietIsOptional(t *testing.T) {
	if strings.Contains(bootArgs(Options{Arch: "aarch64"}, ""), "quiet") {
		t.Error("verbose boot must not pass quiet")
	}
	if !strings.Contains(bootArgs(Options{Arch: "aarch64", Quiet: true}, ""), "quiet") {
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
	args := bootArgs(Options{Arch: "aarch64", Quiet: true}, "")
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
	args := bootArgs(Options{Arch: "aarch64", Quiet: true, Net: n}, "")
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
	if got := bootArgs(Options{Arch: "aarch64", Quiet: true}, ""); strings.Contains(got, "kelyfos.scratch") {
		t.Errorf("an uncapped sandbox still names a scratch size: %s", got)
	}
	got := bootArgs(Options{Arch: "aarch64", Quiet: true, Workspace: &Workspace{}, ScratchBytes: 64 << 20}, "")
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
	if got := bootArgs(Options{Arch: "x86_64", Quiet: true}, ""); strings.Contains(got, "kelyfos.agent") {
		t.Errorf("a sandbox with no team still names an agent: %s", got)
	}
	got := bootArgs(Options{Arch: "x86_64", Quiet: true, Agent: "worker-2"}, "")
	if !strings.Contains(got, "kelyfos.agent=worker-2") {
		t.Errorf("the agent name is missing: %s", got)
	}
}

// A spawn budget is the host's answer, and the guest is told it on the same
// channel as its own name — so the tool is listed only where it can work.
func TestSpawnPermissionRidesTheCommandLine(t *testing.T) {
	if got := bootArgs(Options{Arch: "aarch64", Quiet: true, Agent: "master"}, ""); strings.Contains(got, "kelyfos.spawn") {
		t.Errorf("an agent with no budget is told it may spawn: %s", got)
	}
	if got := bootArgs(Options{Arch: "aarch64", Quiet: true, Agent: "master", MaySpawn: true}, ""); !strings.Contains(got, "kelyfos.spawn=1") {
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
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	// Through RunDirOf rather than a bare temp directory, because the state file
	// now lives beside the chroot and readState checks that the record it finds
	// there is the record of the sandbox that directory is named for (F19).
	dir := RunDirOf("abc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
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
	olderDir := RunDirOf("xyz")
	if err := os.MkdirAll(olderDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir(olderDir), stateFile),
		[]byte(`{"id":"xyz","run_dir":"`+olderDir+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, err := readState(olderDir)
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

// F19. The host's own record of a sandbox lived inside the VMM's chroot.
//
// The jailer chroots Firecracker into the run directory and drops it to the
// invoking uid — the same uid that owns sandbox.json and the pause marker, both
// at 0600, both in that directory. A VMM that has been compromised (the threat
// the jail exists for, and the one docs/threat-model.md calls "depth, not a
// boundary") could rewrite either, and every later kelyfos process obeyed what
// it read: pause copies WorkspaceHost into the stored session and resume renames
// the guest's tree over that host directory; `snapshot save` copies the
// addressing into the snapshot the next guest boots from; exec and shell dial
// UDSPath.
//
// jailDir(id) is one level above the chroot and is not reachable from inside it.
// That is where the host's own record belongs.
func TestF19_TheStateFileIsOutsideTheVMMsChroot(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	const id = "abc12345"
	runDir := RunDirOf(id)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}

	s := &Sandbox{State: State{
		ID: id, RunDir: runDir,
		UDSPath: filepath.Join(runDir, "v.sock"),
		APIPath: filepath.Join(runDir, "fc.sock"),
	}}
	if err := s.writeState(); err != nil {
		t.Fatal(err)
	}

	// The chroot root is runDir. A file inside it is a file the VMM can open.
	if _, err := os.Stat(filepath.Join(runDir, stateFile)); err == nil {
		t.Errorf("%s is inside the chroot (%s), where the VMM can rewrite it — and every later "+
			"kelyfos process trusts what it reads there", stateFile, runDir)
	}
	outside := filepath.Join(jailDir(id), stateFile)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the state is not at %s either: %v", outside, err)
	}
	if withinDir(outside, runDir) {
		t.Errorf("%s is still under the chroot root %s", outside, runDir)
	}

	// The pause marker is the other half: it is what tells the process holding
	// the sandbox that this stop is a pause and the workspace must not be
	// written back.
	if withinDir(PauseMarker(&s.State), runDir) {
		t.Errorf("the pause marker %s is inside the chroot; a VMM that plants one makes a run "+
			"skip its sync-back for ever", PauseMarker(&s.State))
	}

	// And it still round-trips, which is the whole point of moving rather than
	// removing it.
	back, err := readState(runDir)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if back.ID != id || back.UDSPath != s.State.UDSPath {
		t.Errorf("state came back as %+v", back)
	}
}

// F19, the second part: validate on read regardless.
//
// The move above is what closes the finding — a chrooted process cannot walk
// above its own root — but the file is still the one thing several commands
// believe without question, and `--no-jail` exists. So every field a later
// process turns into a host action is checked against something this process
// can derive for itself.
//
// The network half is not in the review and belongs here anyway. F9 gives the
// egress proxy a Peer address and refuses a connection from anywhere else; on
// the restore path that address comes from this file, through SnapshotRunning
// into the snapshot's meta.json and out again through restoreNetwork into
// newNetworkAt. A compromised VMM cannot write a *malformed* address — F9's
// up() refuses that — but it can write a valid and wrong one. 127.0.0.1 is the
// example that matters: it is an address a local host process can source from,
// which turns the peer check into a check that passes for the wrong peer and
// leaves only the nftables layer refusing.
func TestF19_ARewrittenStateFileIsRefusedRatherThanObeyed(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("KELYFOS_CACHE", cache)
	const id = "0901977d"
	runDir := RunDirOf(id)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The shape a live sandbox actually writes, taken from a running machine's
	// own sandbox.json. It has to keep loading, or this check is a way to lose
	// every running sandbox rather than a way to distrust a rewritten one.
	sound := func() State {
		return State{
			ID: id, PID: os.Getpid(), Arch: "aarch64", Flavor: "dev",
			UDSPath: filepath.Join(runDir, "v.sock"),
			APIPath: filepath.Join(runDir, "fc.sock"),
			TAP:     "kelyfos" + id,
			HostIP:  "169.254.36.5", GuestIP: "169.254.36.6",
			Netmask: "255.255.255.252", HostMAC: "02:01:09:01:97:7d",
			ProxyPort: 41809, VcpuCount: 2, MemMiB: 512,
			Allow: []string{"example.com"}, RunDir: runDir, Jailed: true,
		}
	}
	// Written to both places on purpose. The parent commit reads the copy inside
	// the chroot and this one reads the copy above it, so every case below
	// reports what it is really about — the value being obeyed — on either side
	// of the fix, rather than reporting a missing file on one of them.
	write := func(t *testing.T, st State) {
		t.Helper()
		blob, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range []string{jailDir(id), runDir} {
			if err := os.WriteFile(filepath.Join(dir, stateFile), blob, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	// What the jailer leaves in the chroot, as root and mode 0644 — readable by
	// the VMM, not writable by it.
	if err := os.WriteFile(filepath.Join(runDir, "firecracker.pid"),
		[]byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	write(t, sound())
	if _, err := readState(runDir); err != nil {
		t.Fatalf("a state file a real machine wrote was refused: %v", err)
	}

	for _, c := range []struct {
		name string
		bend func(*State)
		why  string
	}{
		{"run-dir-elsewhere", func(st *State) { st.RunDir = "/home/somebody" },
			"RunDir is derivable from the id; a rewritten one aims every path built from it"},
		{"id-not-its-own-directory", func(st *State) {
			// The network fields go too, or validateNetwork's TAP check refuses
			// this first — the TAP is derived from the id — and the id check
			// itself is never reached. That is how this case passed while
			// validate()'s own first line did nothing.
			st.ID = "deadbeef"
			st.TAP, st.HostIP, st.GuestIP, st.Netmask, st.HostMAC, st.ProxyPort = "", "", "", "", "", 0
		},
			"the file at <id>/sandbox.json claiming to be another sandbox is one machine answering for another"},
		{"uds-outside-the-run-dir", func(st *State) { st.UDSPath = "/tmp/anywhere.sock" },
			"exec and shell dial this"},
		{"api-outside-the-run-dir", func(st *State) { st.APIPath = "/tmp/anywhere.sock" },
			"snapshot save and pause drive the VMM through this"},
		{"workspace-image-outside-the-cache", func(st *State) { st.Workspace = "/etc/passwd" },
			"snapshot save copies this file into the snapshot the next guest boots from"},
		{"plugins-outside-the-cache", func(st *State) { st.Plugins = "/etc/shadow" },
			"the plugins device is packed into the guest"},
		{"workspace-host-inside-the-cache", func(st *State) {
			st.WorkspaceHost = filepath.Join(cache, "sessions")
		},
			"resume renames the guest's tree over WorkspaceHost; kelyfos's own state is not a project"},
		{"workspace-host-relative", func(st *State) { st.WorkspaceHost = "proj/../../etc" },
			"a path that is not absolute and clean is not a directory anybody chose"},
		{"guest-ip-is-loopback", func(st *State) { st.GuestIP = "127.0.0.1" },
			"the restore hands this to the egress proxy as its Peer, and a local process can source from it (F9)"},
		{"host-ip-is-loopback", func(st *State) { st.HostIP = "127.0.0.1" },
			"the proxy binds here and the nftables rule is written for it"},
		{"guest-ip-not-the-pair-of-the-host-ip", func(st *State) { st.GuestIP = "169.254.36.9" },
			"the addressing is a derived /30; a pair that is not one was not derived"},
		{"host-ip-off-the-link-local-range", func(st *State) {
			st.HostIP, st.GuestIP = "10.0.0.1", "10.0.0.2"
		},
			"deriveAddrs only ever produces 169.254.0.0/16"},
		{"host-ip-in-the-metadata-slash-30", func(st *State) {
			st.HostIP, st.GuestIP = "169.254.169.253", "169.254.169.254"
		},
			"deriveAddrs refuses this one index; a state file naming it did not come from it"},
		{"netmask-widened", func(st *State) { st.Netmask = "255.255.0.0" },
			"a /16 handed to `ip addr add` claims the whole link-local range for this sandbox"},
		{"tap-not-the-derived-name", func(st *State) { st.TAP = "eth0" },
			"Sample() reads /sys/class/net/<tap>/statistics from this, so a rewritten one files " +
				"another interface's traffic in the flight recorder under this sandbox's name"},
		{"host-mac-malformed", func(st *State) { st.HostMAC = "not-a-mac" },
			"this is the argument to `ip link set … address`"},
		{"host-mac-not-locally-administered", func(st *State) { st.HostMAC = "01:00:5e:00:00:01" },
			"a multicast MAC on a TAP is not something this package mints"},
		{"proxy-port-out-of-range", func(st *State) { st.ProxyPort = 70000 },
			"this goes into the nftables rule as the one reachable port"},
		{"pid-is-not-the-one-the-jailer-recorded", func(st *State) { st.PID = 999999 },
			"the jailer writes firecracker.pid as root inside the chroot, so the VMM can read it " +
				"and cannot rewrite it — it is the one thing in there this host can still believe"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := sound()
			c.bend(&st)
			write(t, st)
			if _, err := readState(runDir); err == nil {
				t.Errorf("a rewritten sandbox.json was obeyed rather than refused — %s", c.why)
			}
		})
	}

	// The bound on the pid, on its own. It has to be tested where there is no
	// jailer pid file to cross-check against — which is what --no-jail leaves —
	// or the cross-check refuses this first and the bound is never reached.
	t.Run("pid-negative-with-no-jailer-file", func(t *testing.T) {
		const unjailed = "aabbccdd"
		dir := RunDirOf(unjailed)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		st := sound()
		st.ID, st.RunDir, st.PID, st.Jailed = unjailed, dir, -1, false
		st.UDSPath, st.APIPath = filepath.Join(dir, "v.sock"), filepath.Join(dir, "fc.sock")
		st.TAP, st.HostIP, st.GuestIP, st.Netmask, st.HostMAC, st.ProxyPort = "", "", "", "", "", 0
		blob, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(jailDir(unjailed), stateFile), blob, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readState(dir); err == nil {
			t.Error("a negative pid was accepted — alive() signals this and Sample() reads " +
				"/proc/<pid>/io from it")
		}
	})

	// A state file written before a field existed still loads. The check is
	// about values a VMM could have chosen, not about being new.
	t.Run("older-state-file-still-loads", func(t *testing.T) {
		st := sound()
		st.TAP, st.HostIP, st.GuestIP, st.Netmask, st.HostMAC, st.ProxyPort = "", "", "", "", "", 0
		st.Seccomp, st.Profile = "", ""
		write(t, st)
		if _, err := readState(runDir); err != nil {
			t.Errorf("a sandbox with no network was refused: %v", err)
		}
	})
}
