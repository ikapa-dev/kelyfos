// Package scope holds the test for dev/scope.sh, the teardown the dev suites
// share. The suites themselves need a real machine — KVM, Firecracker and the
// dev image — so nothing on a pull request runs them; this is the cheap check
// that does run on every commit, the same relationship tools/cookbook's test
// has to dev/cookbook.sh.
//
// What it pins is the one property whose absence is silent (D79): a teardown
// that has stopped being scoped does not fail, it stops killing anything, or
// it kills somebody else's machines and the suite still reports PASS.
package scope

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startFakeFirecracker runs a harmless long sleep under the name
// "firecracker", so that a host-wide `pgrep firecracker` — the idiom this
// change removes — matches it. That is what makes this test discriminating
// rather than decorative: put `pgrep firecracker` back into scope_pids and the
// peer below dies and this test goes red.
func startFakeFirecracker(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	bin := filepath.Join(dir, "firecracker")
	src, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Skipf("no /bin/sleep to copy: %v", err)
	}
	if err := os.WriteFile(bin, src, 0o755); err != nil {
		t.Fatalf("writing the stand-in: %v", err)
	}
	cmd := exec.Command(bin, "600")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the stand-in: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

// alive reports whether pid is a process that has not been signalled away. A
// zombie answers kill -0 successfully, so asking that way would report a
// machine this teardown had just killed as still running — which is how the
// first version of this test's own manual reproduction fooled its author.
func alive(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}
	// The comm field is parenthesised and may contain spaces; state follows it.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) {
		return false
	}
	return string(b)[i+2] != 'Z'
}

func writePidFile(t *testing.T, cache string, id string, pid int) {
	t.Helper()
	dir := filepath.Join(cache, "run", "firecracker", id, "root")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "firecracker.pid"),
		[]byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(wd)) // tools/scope -> repo root
}

// TestScopeTeardownKillsItsOwnMachinesAndNobodyElses is the whole point of
// dev/scope.sh. Two sandboxes exist, each with its own KELYFOS_CACHE and its
// own firecracker.pid; the teardown is run against one of them; the other must
// still be running afterwards.
func TestScopeTeardownKillsItsOwnMachinesAndNobodyElses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc and signals processes; the dev suites are Linux-only anyway")
	}
	root := repoRoot(t)
	script := filepath.Join(root, "dev", "scope.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("dev/scope.sh is missing: %v", err)
	}

	ourCache := t.TempDir()
	peerCache := t.TempDir()

	ours := startFakeFirecracker(t, t.TempDir())
	peer := startFakeFirecracker(t, t.TempDir())

	writePidFile(t, ourCache, "aaaaaaaa", ours.Process.Pid)
	writePidFile(t, peerCache, "bbbbbbbb", peer.Process.Pid)

	if !alive(ours.Process.Pid) || !alive(peer.Process.Pid) {
		t.Fatal("both stand-ins must be running before the teardown")
	}

	cmd := exec.Command("bash", "-c",
		`set -u; source "$1"; KELYFOS_CACHE="$2"; export KELYFOS_CACHE; scope_teardown`,
		"bash", script, ourCache)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("scope_teardown failed: %v\n%s", err, out)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && alive(ours.Process.Pid) {
		time.Sleep(50 * time.Millisecond)
	}

	if alive(ours.Process.Pid) {
		t.Errorf("scope_teardown left this run's own machine (pid %d) running — "+
			"a teardown that stops killing anything is the silent half of D79",
			ours.Process.Pid)
	}
	if !alive(peer.Process.Pid) {
		t.Errorf("scope_teardown killed a peer's machine (pid %d), which is the "+
			"whole defect: it must ask whether ITS OWN sandboxes are gone, not "+
			"whether any Firecracker is running on this host.\nteardown said: %s",
			peer.Process.Pid, out)
	}
}

// TestScopePidsReadsOnlyItsOwnCache pins the narrower half directly, so a
// regression in scope_pids is named by the test that breaks rather than only
// by the one above.
func TestScopePidsReadsOnlyItsOwnCache(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the dev suites are Linux-only")
	}
	root := repoRoot(t)
	ourCache := t.TempDir()
	peerCache := t.TempDir()
	writePidFile(t, ourCache, "aaaaaaaa", 11111)
	writePidFile(t, peerCache, "bbbbbbbb", 22222)

	cmd := exec.Command("bash", "-c",
		`set -u; source "$1"; KELYFOS_CACHE="$2"; export KELYFOS_CACHE; scope_pids`,
		"bash", filepath.Join(root, "dev", "scope.sh"), ourCache)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("scope_pids failed: %v", err)
	}
	got := strings.Fields(string(out))
	if len(got) != 1 || got[0] != "11111" {
		t.Errorf("scope_pids returned %v; it must return only the pid under its "+
			"own KELYFOS_CACHE (11111), never the peer's (22222)", got)
	}
}

// buildFakeKelyfos makes a stand-in whose comm really is "kelyfos" and whose
// argv[1] is a chosen subcommand — the two things the predicates read. A shell
// script will not do: comm comes from the executable, so a script's process is
// named after its interpreter and `pgrep -x kelyfos` never sees it. So /bin/sh
// is copied to a file called "kelyfos" and handed a script named after the
// subcommand, which puts that word in argv[1] exactly where a real invocation
// would have it.
func buildFakeKelyfos(t *testing.T, dir string, subcommands ...string) string {
	t.Helper()
	sh, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Skipf("no /bin/sh to copy: %v", err)
	}
	bin := filepath.Join(dir, "kelyfos")
	if err := os.WriteFile(bin, sh, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sub := range subcommands {
		if err := os.WriteFile(filepath.Join(dir, sub), []byte("sleep 600\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return bin
}

func startFake(t *testing.T, bin, cache string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = filepath.Dir(bin)
	cmd.Env = append(os.Environ(), "KELYFOS_CACHE="+cache)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd
}

func runScope(t *testing.T, cache, snippet string) string {
	t.Helper()
	out, err := exec.Command("bash", "-c",
		`set -u; source "$1"; KELYFOS_CACHE="$2"; export KELYFOS_CACHE; `+snippet,
		"bash", filepath.Join(repoRoot(t), "dev", "scope.sh"), cache).CombinedOutput()
	if err != nil {
		t.Fatalf("scope.sh snippet %q failed: %v\n%s", snippet, err, out)
	}
	return string(out)
}

// TestScopePidsToleratesAPidFileWithNoTrailingNewline is a regression test for a
// defect this change shipped and a live run caught: the jailer writes
// firecracker.pid with no trailing newline, so cat-ing a pid file and a
// sandbox.json pid in sequence produced "111222" — one token that is not a pid,
// which the teardown then failed to kill while reporting nothing wrong.
func TestScopePidsToleratesAPidFileWithNoTrailingNewline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the dev suites are Linux-only")
	}
	cache := t.TempDir()
	dir := filepath.Join(cache, "run", "firecracker", "aaaaaaaa")
	if err := os.MkdirAll(filepath.Join(dir, "root"), 0o755); err != nil {
		t.Fatal(err)
	}
	// One jailed sandbox writes BOTH: the jailer's pid file, with no trailing
	// newline, and its own state file naming the same pid. That is where the
	// two reads meet, and where "111" + "111" became "111111".
	if err := os.WriteFile(filepath.Join(dir, "root", "firecracker.pid"),
		[]byte("111"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"),
		[]byte(`{"id":"aaaaaaaa","pid":111,"jailed":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(runScope(t, cache, "scope_pids"))
	sort.Strings(got)
	if len(got) != 1 || got[0] != "111" {
		t.Errorf("scope_pids returned %v, want [111]; the jailer writes firecracker.pid "+
			"with no trailing newline, so an unframed read concatenates it with the "+
			"state file's pid into a token that is not a pid and cannot be killed", got)
	}
}

// TestScopePidsFindsAnUnjailedMachine pins the blocker the review found:
// firecracker.pid is written by the jailer, so a --no-jail sandbox has none,
// and a teardown reading only that file walks past the machine and reports
// success. dev/accept-jail.sh and dev/accept-seccomp.sh both boot --no-jail.
func TestScopePidsFindsAnUnjailedMachine(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the dev suites are Linux-only")
	}
	cache := t.TempDir()
	dir := filepath.Join(cache, "run", "firecracker", "cccccccc")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// What an unjailed run leaves behind: a state file with its pid, and no
	// firecracker.pid anywhere.
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"),
		[]byte(`{"id":"cccccccc","pid":31337,"jailed":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(runScope(t, cache, "scope_pids"))
	if len(got) != 1 || got[0] != "31337" {
		t.Errorf("scope_pids returned %v; an unjailed machine records its pid only in "+
			"sandbox.json, and a teardown that cannot see it leaks the machine silently", got)
	}
}

// TestScopeOwnKelyfosPidsMatchesOnTheCacheNotTheName pins the predicate that
// replaced `pkill -f "kelyfos run"`. It is the most novel thing in scope.sh and
// was untested until the review said so.
func TestScopeOwnKelyfosPidsMatchesOnTheCacheNotTheName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/<pid>/environ")
	}
	bin := buildFakeKelyfos(t, t.TempDir(), "run")
	ourCache, peerCache := t.TempDir(), t.TempDir()

	ours := startFake(t, bin, ourCache, "run")
	peer := startFake(t, bin, peerCache, "run")
	time.Sleep(300 * time.Millisecond)

	got := strings.Fields(runScope(t, ourCache, "scope_own_kelyfos_pids"))
	if !slicesContain(got, strconv.Itoa(ours.Process.Pid)) {
		t.Errorf("scope_own_kelyfos_pids %v omitted this run's own kelyfos (pid %d)",
			got, ours.Process.Pid)
	}
	if slicesContain(got, strconv.Itoa(peer.Process.Pid)) {
		t.Errorf("scope_own_kelyfos_pids %v included a peer's kelyfos (pid %d) — it must "+
			"match on KELYFOS_CACHE in the environment, never on the process name",
			got, peer.Process.Pid)
	}
}

// TestScopeKillKelyfosHonoursItsSubcommandFilter pins the defect that broke
// dev/accept-profile.sh: halt() was `pkill -f "kelyfos run"`, which by
// construction spares a `kelyfos snapshot restore`, and the suite execs into
// the machine that restore brought up.
func TestScopeKillKelyfosHonoursItsSubcommandFilter(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc/<pid>/cmdline")
	}
	bin := buildFakeKelyfos(t, t.TempDir(), "run", "snapshot")
	cache := t.TempDir()

	run := startFake(t, bin, cache, "run")
	restore := startFake(t, bin, cache, "snapshot", "restore", "--workspace", "/srv/run/x")
	time.Sleep(300 * time.Millisecond)

	runScope(t, cache, "scope_kill_kelyfos run")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && alive(run.Process.Pid) {
		time.Sleep(50 * time.Millisecond)
	}
	if alive(run.Process.Pid) {
		t.Errorf("scope_kill_kelyfos run left the `kelyfos run` (pid %d) alive", run.Process.Pid)
	}
	if !alive(restore.Process.Pid) {
		t.Errorf("scope_kill_kelyfos run killed a `kelyfos snapshot restore` (pid %d). "+
			"`pkill -f \"kelyfos run\"` never did, and dev/accept-profile.sh execs into "+
			"the machine that restore brought up", restore.Process.Pid)
	}
}

func slicesContain(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
