package sandbox

import (
	"os"
	"path/filepath"
	"strings"
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

// A team places its scopes in a slice systemd owns, and every child carries an
// equal weight. The single-run request above must be unchanged by that, which
// is what TestWrapArgvBuildsTheScopeRequest is now also guarding.
func TestWrapArgvPlacesTheScopeInTheTeamSlice(t *testing.T) {
	s := &Slice{Percent: 150, Weight: DefaultCPUWeight, name: "kelyfos-abc",
		mode: modeSystemd, sliceUnit: "kelyfos-team-demo.slice"}
	want := []string{"systemd-run", "--user", "--scope", "--quiet",
		"--unit", "kelyfos-abc", "--slice", "kelyfos-team-demo.slice",
		"-p", "CPUQuota=150%", "-p", "CPUWeight=100", "--", "firecracker"}
	got := s.WrapArgv([]string{"firecracker"})
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg %d: got %q want %q\nfull: %v", i, got[i], want[i], got)
		}
	}

	// An agent with no quota of its own is bounded by the team's, so the
	// CPUQuota property must be absent rather than sent as zero — which systemd
	// would read as a request, not as an absence.
	none := &Slice{Weight: DefaultCPUWeight, name: "kelyfos-def",
		mode: modeSystemd, sliceUnit: "kelyfos-team-demo.slice"}
	for _, arg := range none.WrapArgv([]string{"firecracker"}) {
		if arg == "CPUQuota=0%" || arg == "CPUQuota=" {
			t.Fatalf("an agent with no quota asked for one: %v", none.WrapArgv([]string{"firecracker"}))
		}
	}
}

// The dash is systemd's hierarchy separator, so a team called "foo-bar" would
// silently add a level and cap something other than the team. The team's own
// name is always exactly one component.
func TestATeamNameIsAlwaysOneSliceComponent(t *testing.T) {
	for _, name := range []string{"demo", "foo-bar", "Ops Team", "a/b", "", "..", "réviseurs"} {
		got := teamSliceName(name)
		tail, ok := strings.CutPrefix(got, "kelyfos-team-")
		if !ok {
			t.Fatalf("teamSliceName(%q) = %q, which is not under the KelyfOS root", name, got)
		}
		if tail == "" {
			t.Errorf("teamSliceName(%q) named nothing", name)
		}
		if strings.ContainsAny(tail, "-/. ") {
			t.Errorf("teamSliceName(%q) = %q, whose team part is more than one component", name, got)
		}
	}
}

// A child with no quota of its own has no cpu.max to compare, so placement is
// the only thing left to check — and it has to be checked, because Close
// removes whatever path the confirm adopted.
func TestPlacementIsCheckedWhenThereIsNoQuota(t *testing.T) {
	cases := []struct {
		name, landed, parent, unit string
		ok                         bool
	}{
		{"direct, inside the team slice", "/sys/fs/cgroup/kt/kelyfos-a", "/sys/fs/cgroup/kt", "", true},
		{"direct, the team slice itself", "/sys/fs/cgroup/kt", "/sys/fs/cgroup/kt", "", true},
		{"direct, somewhere else", "/sys/fs/cgroup/other/x", "/sys/fs/cgroup/kt", "", false},
		{"direct, a sibling with the same prefix", "/sys/fs/cgroup/kt2/x", "/sys/fs/cgroup/kt", "", false},
		{"systemd, in the team's slice", "/sys/fs/cgroup/u/kelyfos-team-d.slice/kelyfos-a.scope",
			"", "kelyfos-team-d.slice", true},
		{"systemd, in another slice", "/sys/fs/cgroup/u/app.slice/kelyfos-a.scope",
			"", "kelyfos-team-d.slice", false},
		{"no parent expected", "/sys/fs/cgroup/anywhere", "", "", true},
	}
	for _, c := range cases {
		err := underParent(c.landed, c.parent, c.unit)
		if c.ok && err != nil {
			t.Errorf("%s: rejected a correct placement: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted a process that landed in %q", c.name, c.landed)
		}
	}
}

// A single run has no team above it, and for that reason nothing used to check
// where its VMM actually landed: parent went unset, so the placement check
// returned nil without asking anything and cpu.max was the whole of the
// verification. cpu.max is a value some other cgroup can happen to share, and
// Close removes whatever Path holds, so agreeing on a number is not the same as
// having landed in our slice.
func TestASingleRunKnowsWhereItsProcessMustLand(t *testing.T) {
	root := t.TempDir()
	sl := &Slice{Percent: 150, name: "kelyfos-abc", mode: modeDirect}
	if err := sl.prepareDirect(root); err != nil {
		t.Fatalf("prepare the slice: %v", err)
	}
	defer sl.Close()
	own := sl.Path

	// The caller's own cgroup on a host where the placement was a silent no-op:
	// the VMM never moved, and this one happens to carry the same cap.
	elsewhere := t.TempDir()
	if err := os.WriteFile(filepath.Join(elsewhere, "cpu.max"), []byte(cpuMaxLine(150)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sl.confirmAt(elsewhere); err == nil {
		t.Error("a VMM that never reached the slice was confirmed, because another cgroup's cpu.max matched")
	}
	if sl.Path != own {
		t.Errorf("Path moved to %s, which Close would then remove, leaking %s", sl.Path, own)
	}

	// A jailer that nests the VMM one level below the slice is still inside it,
	// so the check has to tolerate that as well as the exact landing.
	nested := filepath.Join(own, "firecracker")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "cpu.max"), []byte(cpuMaxLine(150)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sl.confirmAt(nested); err != nil {
		t.Errorf("a VMM nested inside our own slice was rejected: %v", err)
	}
	if err := sl.confirmAt(own); err != nil {
		t.Errorf("the slice this run made for itself was rejected: %v", err)
	}
}

// Refusing the run is not the whole of the protection. Path used to be adopted
// before the cpu.max comparison, so a confirm that then failed handed the
// deferred Close a directory the VMM had strayed into and left the slice we
// really made behind. The team path sets parent, and was no better off: the
// stray only has to be somewhere inside the team's slice.
func TestAFailedConfirmDoesNotAdoptWhereTheProcessLanded(t *testing.T) {
	team := t.TempDir()
	dir := func(name string, cpuMax, weight string) string {
		p := filepath.Join(team, name)
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "cpu.max"), []byte(cpuMax), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "cpu.weight"), []byte(weight), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	own := dir("kelyfos-a", cpuMaxLine(150), cpuWeightLine(DefaultCPUWeight))
	member := func() *Slice {
		return &Slice{Percent: 150, Weight: DefaultCPUWeight, name: "kelyfos-a",
			mode: modeDirect, parent: team, Path: own}
	}

	// Inside the team's slice, so the placement check is content — but a cgroup
	// nobody wrote our cap into, which reads back as the kernel's default.
	strayed := dir("strayed", "max 100000", cpuWeightLine(DefaultCPUWeight))
	s := member()
	if err := s.confirmAt(strayed); err == nil {
		t.Error("a cgroup carrying no cap at all was confirmed as the quota")
	}
	if s.Path != own {
		t.Errorf("a failed confirm left Path at %s, so Close removes that and leaks %s", s.Path, own)
	}

	// The weight is compared after the quota, so it is the second chance to
	// adopt something unverified.
	odd := dir("odd-weight", cpuMaxLine(150), "1")
	s = member()
	if err := s.confirmAt(odd); err == nil {
		t.Error("a cgroup carrying somebody else's weight was confirmed")
	}
	if s.Path != own {
		t.Errorf("a failed weight check left Path at %s, want %s", s.Path, own)
	}

	// And when every check passes the landing is recorded, which is how the
	// systemd path learns the directory systemd chose for the scope.
	good := dir("kelyfos-a.scope", cpuMaxLine(150), cpuWeightLine(DefaultCPUWeight))
	s = member()
	if err := s.confirmAt(good); err != nil {
		t.Fatalf("a correct placement was rejected: %v", err)
	}
	if s.Path != good {
		t.Errorf("a confirmed placement was not recorded: Path is %s, want %s", s.Path, good)
	}
}
