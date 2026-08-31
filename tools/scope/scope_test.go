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
