package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// The percentage never reaches the kernel: E1-2 fixes the translation exactly,
// and these are the numbers it names.
func TestCPUMaxLineMapsPercentToMicroseconds(t *testing.T) {
	cases := map[int]string{
		150: "150000 100000",
		50:  "50000 100000",
		100: "100000 100000",
		25:  "25000 100000",
		400: "400000 100000",
	}
	for pct, want := range cases {
		if got := cpuMaxLine(pct); got != want {
			t.Errorf("cpuMaxLine(%d%%) = %q, want %q", pct, got, want)
		}
	}
}

func TestNewCPUSliceRejectsNonPositiveQuota(t *testing.T) {
	for _, pct := range []int{0, -1, -100} {
		if _, err := NewCPUSlice("test", pct); err == nil {
			t.Errorf("NewCPUSlice accepted %d%%", pct)
		}
	}
}

// Under systemd the quota is requested rather than written, and the request has
// to carry the same percentage the CLI was given.
func TestWrapArgvBuildsTheScopeRequest(t *testing.T) {
	s := &Slice{Percent: 150, name: "kelyfos-abc", mode: modeSystemd}
	got := s.WrapArgv([]string{"firecracker", "--api-sock", "/x"})
	want := []string{"systemd-run", "--user", "--scope", "--quiet",
		"--unit", "kelyfos-abc", "-p", "CPUQuota=150%", "--",
		"firecracker", "--api-sock", "/x"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d: got %q want %q\nfull: %v", i, got[i], want[i], got)
		}
	}
	// The direct path must not rewrite the command at all.
	d := &Slice{Percent: 150, mode: modeDirect}
	if out := d.WrapArgv([]string{"firecracker"}); len(out) != 1 || out[0] != "firecracker" {
		t.Errorf("direct path rewrote argv: %v", out)
	}
	if out := (*Slice)(nil).WrapArgv([]string{"firecracker"}); len(out) != 1 {
		t.Errorf("nil slice rewrote argv: %v", out)
	}
}

// The difference between "this cgroup has the cpu controller" and "this cgroup
// gives the cpu controller to its children" is the whole of the bug a bare-KVM
// runner found, so it is pinned here with the two files that decide it.
func TestDelegationIsCheckedNotAvailability(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A GitHub runner's own cgroup: it has cpu, and hands nothing down.
	write("cgroup.controllers", "cpuset cpu io memory pids\n")
	write("cgroup.subtree_control", "\n")
	if err := hasCPUController(dir); err != nil {
		t.Fatalf("the controller is present, so this check should pass: %v", err)
	}
	if err := delegatesCPU(dir); err == nil {
		t.Error("a cgroup that delegates nothing was accepted as a place to create a quota")
	}

	// Once it delegates, it is usable.
	write("cgroup.subtree_control", "cpu memory\n")
	if err := delegatesCPU(dir); err != nil {
		t.Errorf("a cgroup that delegates cpu was rejected: %v", err)
	}

	// And a cgroup without the controller at all cannot delegate it, however
	// hard it is asked.
	write("cgroup.controllers", "cpuset io memory pids\n")
	write("cgroup.subtree_control", "\n")
	if err := delegateCPU(dir); err == nil {
		t.Error("a cgroup with no cpu controller was talked into delegating one")
	}
}
