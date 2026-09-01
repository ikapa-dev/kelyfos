package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// cpuPeriodUS is the accounting window for the quota. 100 ms is the cgroup v2
// default and short enough that throttling feels like a slower machine rather
// than a stuttering one.
const cpuPeriodUS = 100000

// DefaultCPUWeight is cgroup v2's own default, and the weight every agent in a
// team gets. Equal weights are what E2-6's "divides contention fairly" means:
// nothing is privileged, and the parent's bandwidth splits evenly among
// whichever siblings are actually competing for it. Written explicitly rather
// than left to the kernel, so "no agent was privileged" is something the proof
// reads back instead of something the code assumes.
const DefaultCPUWeight = 100

// systemdScopePreflightTimeout bounds the boot-path check that systemd-run
// actually works (audit 2026-09-01, A17b). In an environment with no cgroup
// delegation and no working user systemd session, the boot used to sit after
// session.start with no refusal and no output — the scope request blocked on a
// D-Bus call with no timeout while the caller waited for a machine that was
// never going to come up. A boot-path preflight that cannot finish inside
// this bound is a machine that cannot be quotaed, and it is refused by name
// instead of discovered at the timeout nobody set.
const systemdScopePreflightTimeout = 4 * time.Second

// Slice is a cgroup v2 directory holding one sandbox's Firecracker process.
//
// It exists so `cpu_quota` can cap the CPU time a sandbox actually consumes,
// which is a different question from how many cores it can see (E1-2, and the
// distinction docs/resources.md spells out). The guest cannot influence it:
// this is a host-side control on the VMM process, which is the only place a
// limit on untrusted code is worth anything (F-D2).
//
// The jailer landed at P5-1 and did not take this over: it creates cgroups only
// when given --cgroup arguments, which KelyfOS does not use. What it does
// instead is move its own process into a cgroup this package already made and
// configured — see jailArgv — so the slice stays owned here and the jail simply
// starts inside it.
type Slice struct {
	Path    string
	Percent int
	// Weight divides contention between siblings under a shared parent — a
	// share, not a ceiling, and meaningless to a sandbox with no siblings.
	// Zero leaves it unset, which is what a single run wants (E2-6).
	Weight int
	name   string
	mode   mode
	dir    *os.File

	// Where this slice expects its process to land. parent is the absolute
	// directory on the direct path — its own directory for a single run, the
	// team's for one member of a team — and sliceUnit is the systemd unit name
	// on the other. Confirm checks the process landed there, which matters most
	// for a child with no quota of its own: without a placement check there
	// would be nothing left to verify, and Close would then be holding a path
	// nobody proved was ours. Both are empty only for a plain systemd scope,
	// whose placement is the user manager's to choose and not ours to assert.
	parent    string
	sliceUnit string
}

// mode is how this host lets an unprivileged process get a CPU quota.
type mode int

const (
	modeDirect  mode = iota // we can create and populate the cgroup ourselves
	modeSystemd             // the user manager has to do the move for us
)

// pickMode decides how the quota will be applied on this machine.
//
// The direct path needs more than a writable directory: cgroup v2 requires
// write access to the common ancestor of the source and target cgroups to move
// a process between them. In a login session the source is session-N.scope and
// the delegated subtree is user@UID.service, whose common ancestor is
// user-UID.slice — root's. So owning the target proves nothing, and the attempt
// fails as a bare EACCES out of clone3 (F-D11).
func pickMode() (mode, string, error) {
	if fi, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil || fi.IsDir() {
		return 0, "", fmt.Errorf("this machine is not running cgroup v2, so a CPU quota cannot be enforced; " +
			"drop --cpu-quota or use a cgroup v2 host")
	}
	if root := os.Getenv("KELYFOS_CGROUP_ROOT"); root != "" {
		return modeDirect, root, delegatesCPU(root)
	}
	// Root, or a container where the root cgroup is delegated: do it ourselves,
	// so CI and rootless containers do not need systemd present.
	own, err := ownCgroupPath()
	if err == nil && unix.Access(own, unix.W_OK) == nil {
		if err := delegatesCPU(own); err == nil {
			return modeDirect, own, nil
		}
	}
	// As root the root cgroup is the reliable parent, and the only one exempt
	// from cgroup v2's rule that a cgroup may hold processes or distribute
	// controllers but not both — which is exactly why the cgroup this process
	// is already in usually cannot be used.
	if os.Getuid() == 0 {
		if err := delegateCPU("/sys/fs/cgroup"); err == nil {
			return modeDirect, "/sys/fs/cgroup", nil
		}
	}
	if _, err := exec.LookPath("systemd-run"); err == nil {
		return modeSystemd, "", nil
	}
	return 0, "", fmt.Errorf("cannot apply a CPU quota on this machine: the cgroup holding this process is not " +
		"writable and systemd-run is not available.\n" +
		"    Run under a systemd user session, as root, or drop --cpu-quota.")
}

// ownCgroupPath is the cgroup this process is in, per /proc/self/cgroup.
func ownCgroupPath() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join("/sys/fs/cgroup", rest), nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup")
}

// FD is the directory descriptor for SysProcAttr.CgroupFD.
func (s *Slice) FD() int {
	if s == nil || s.dir == nil {
		return -1
	}
	return int(s.dir.Fd())
}

// CPUStat reports cumulative CPU time and throttling for this slice, which is
// what makes "the limit held" a measurement rather than a claim (E1-7, E1-8).
func (s *Slice) CPUStat() (map[string]int64, error) {
	if s == nil {
		return nil, fmt.Errorf("no cgroup slice")
	}
	return CPUStatAt(s.Path)
}

// CPUStatAt reads cpu.stat from a cgroup directory named by path. Exported
// separately because a team's collective figures are read by a *different
// process* — `kelyfos team ps` has the path out of the team state file and no
// Slice to ask.
func CPUStatAt(dir string) (map[string]int64, error) {
	if dir == "" {
		return nil, fmt.Errorf("no cgroup path")
	}
	b, err := os.ReadFile(filepath.Join(dir, "cpu.stat"))
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if v, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				out[f[0]] = v
			}
		}
	}
	return out, nil
}

// Close removes the cgroup. A cgroup with live processes cannot be removed, so
// this is called after teardown; a leftover empty directory is harmless but
// untidy, and leaving one per run would accumulate.
func (s *Slice) Close() {
	if s == nil {
		return
	}
	if s.dir != nil {
		_ = s.dir.Close()
	}
	_ = os.Remove(s.Path)
}

// delegatesCPU checks that a cgroup hands the cpu controller to its *children*,
// which is the only question that matters when the plan is to create one.
//
// cgroup v2 keeps two lists and they answer different questions:
// cgroup.controllers is what this cgroup has, and cgroup.subtree_control is what
// it passes down. A child gets a cpu.max only if the parent's subtree_control
// names cpu, and reading the wrong one of these is not a theoretical mistake —
// it is what this function was doing until a GitHub runner proved it. There the
// job's own cgroup reports the cpu controller and delegates nothing, so KelyfOS
// happily created a directory it could not then write cpu.max into, and every
// sandbox with a quota failed to start three steps later with a bare permission
// denied.
func delegatesCPU(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return fmt.Errorf("read %s/cgroup.subtree_control: %w", dir, err)
	}
	for _, c := range strings.Fields(string(b)) {
		if c == "cpu" {
			return nil
		}
	}
	return fmt.Errorf("%s does not delegate the cpu controller to its children (subtree_control: %q), "+
		"so a cgroup created there cannot have a quota", dir, strings.TrimSpace(string(b)))
}

// delegateCPU is delegatesCPU with one attempt to fix it.
//
// Called on exactly two kinds of cgroup, for the same reason: ones that hold no
// processes. A cgroup that holds processes cannot start distributing
// controllers — the kernel refuses with EBUSY — and every cgroup this process
// could otherwise use holds at least this process. The root cgroup is the
// documented exception to that rule and is the first caller, as root. The
// second is a team slice KelyfOS has just created and put nothing in yet
// (E2-6): a fresh cgroup's subtree_control is empty, so without this its
// children would have no cpu.max at all.
func delegateCPU(dir string) error {
	if err := delegatesCPU(dir); err == nil {
		return nil
	}
	if err := hasCPUController(dir); err != nil {
		return err
	}
	sub := filepath.Join(dir, "cgroup.subtree_control")
	if err := os.WriteFile(sub, []byte("+cpu"), 0o644); err != nil {
		return fmt.Errorf("enable the cpu controller for children of %s: %w", dir, err)
	}
	return delegatesCPU(dir)
}

// hasCPUController checks the cpu controller is available in a cgroup directory
// at all. Necessary but not sufficient — see delegatesCPU for the difference.
func hasCPUController(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.controllers"))
	if err != nil {
		return fmt.Errorf("read %s/cgroup.controllers: %w", dir, err)
	}
	for _, c := range strings.Fields(string(b)) {
		if c == "cpu" {
			return nil
		}
	}
	return fmt.Errorf("the cpu controller is not available in %s (has: %s), so a CPU quota cannot be enforced there",
		dir, strings.TrimSpace(string(b)))
}

// NewCPUSlice prepares the CPU quota for one sandbox.
//
// percent is a share of a single core's worth of CPU time: 100 is one core's
// worth, 150 is one and a half. The percentage never reaches the kernel — it is
// converted here into the integer microseconds cpu.max takes, whichever path
// ends up applying it (E1-2, F-D11).
func NewCPUSlice(id string, percent int) (*Slice, error) {
	if percent <= 0 {
		return nil, fmt.Errorf("cpu quota must be positive, got %d%%", percent)
	}
	m, root, err := pickMode()
	if err != nil {
		return nil, err
	}
	sl := &Slice{Percent: percent, name: "kelyfos-" + id, mode: m}
	if m == modeSystemd {
		// The preflight (audit 2026-09-01, A17b): pickMode chose the systemd
		// path because the binary exists, which is not the same as a working
		// user session for it to talk to. Everything after this point waits
		// on the scope it requests, so what cannot be answered now is
		// refused now — before any machine, TAP or run directory exists —
		// with the fix in the message.
		if err := preflightSystemdScope(sl.name + "-preflight"); err != nil {
			return nil, err
		}
		return sl, nil
	}

	if err := sl.prepareDirect(root); err != nil {
		return nil, err
	}
	return sl, nil
}

// preflightSystemdScope proves the systemd path works before a boot depends
// on it (audit 2026-09-01, A17b): one throwaway transient scope that runs
// true. A scope that cannot be started — no user session, no bus, a hung
// dbus call — fails or times out inside systemdScopePreflightTimeout, and the
// refusal says what is broken and what to do, where before there was a boot
// that hung without a word after session.start.
func preflightSystemdScope(unit string) error {
	ctx, cancel := context.WithTimeout(context.Background(), systemdScopePreflightTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemd-run", "--user", "--scope", "--quiet",
		"--unit", unit, "--", "true")
	// WaitDelay makes Wait stop waiting on the output pipes a hung grandchild
	// may still hold after the context kill — systemd-run's own D-Bus stall
	// is exactly the shape this preflight exists to catch, and without the
	// delay the kill would not actually unblock the read.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	detail := strings.TrimSpace(string(out))
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("cannot apply a CPU quota on this machine: systemd-run --user did not "+
		"complete within %s and this boot will not hang waiting for it (%s).\n"+
		"    Run under a systemd user session with a working bus, as root with a delegated "+
		"cgroup, or drop --cpu-quota.", systemdScopePreflightTimeout, detail)
}

// prepareDirect creates and configures one sandbox's cgroup under root.
//
// Split out of NewCPUSlice because everything it does is a mkdir, a write and
// an open — no cgroupfs is needed to exercise it, which is what lets the
// expectation it records be checked on any machine.
func (sl *Slice) prepareDirect(root string) error {
	sl.Path = filepath.Join(root, sl.name)
	// A single run knows exactly where its VMM belongs — this directory, which
	// CgroupFD puts it in at clone time and which the jailer is handed as
	// --parent-cgroup — so it says so, and Confirm has something to check.
	// Without it the placement check was a no-op on the one path that never has
	// a team above it, leaving cpu.max as the whole of the verification: a value
	// another cgroup can happen to agree with.
	//
	// The expectation is the slice itself and not root: underParent accepts the
	// directory or anything below it, which still tolerates a jailer that nests
	// the VMM one level down, whereas naming root would accept any sibling
	// under it and check very little.
	sl.parent = sl.Path
	if err := os.Mkdir(sl.Path, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create cgroup %s: %w", sl.Path, err)
	}
	if err := os.WriteFile(filepath.Join(sl.Path, "cpu.max"), []byte(cpuMaxLine(sl.Percent)), 0o644); err != nil {
		_ = os.Remove(sl.Path)
		return fmt.Errorf("write cpu.max in %s: %w", sl.Path, err)
	}
	// The directory handle places the child in this cgroup at clone time.
	// Adding the pid afterwards would leave a window in which the process runs
	// uncapped, which for a quota is exactly the wrong window.
	dir, err := os.Open(sl.Path)
	if err != nil {
		_ = os.Remove(sl.Path)
		return err
	}
	sl.dir = dir
	return nil
}

// cpuMaxLine is the whole percentage-to-kernel translation, in one place so the
// two paths cannot disagree about what "150%" means.
func cpuMaxLine(percent int) string {
	return strconv.Itoa(percent*cpuPeriodUS/100) + " " + strconv.Itoa(cpuPeriodUS)
}

// cpuWeightLine is the same idea for the share, in the same place for the same
// reason: the two paths must not be able to disagree about what a weight is.
func cpuWeightLine(weight int) string { return strconv.Itoa(weight) }

// WrapArgv returns the command to actually execute. Under systemd the quota is
// applied by asking the user manager to start the process in a scope it owns;
// on the direct path the argv is unchanged and CgroupFD does the work.
func (s *Slice) WrapArgv(argv []string) []string {
	if s == nil || s.mode != modeSystemd {
		return argv
	}
	pre := []string{"systemd-run", "--user", "--scope", "--quiet", "--unit", s.name}
	// --slice puts the scope under a parent systemd owns, creating that slice
	// and every level above it if they do not exist. It is how a team's
	// hierarchy is built on this path (E2-6, F-D21).
	if s.sliceUnit != "" {
		pre = append(pre, "--slice", s.sliceUnit)
	}
	// A team child may have no quota of its own — it is bounded by its parent —
	// so the property is conditional now rather than always present.
	if s.Percent > 0 {
		pre = append(pre, "-p", fmt.Sprintf("CPUQuota=%d%%", s.Percent))
	}
	if s.Weight > 0 {
		pre = append(pre, "-p", fmt.Sprintf("CPUWeight=%d", s.Weight))
	}
	return append(append(pre, "--"), argv...)
}

// Direct reports whether the caller should pass CgroupFD when launching.
func (s *Slice) Direct() bool { return s != nil && s.mode == modeDirect }

// Confirm locates the cgroup the process actually landed in and verifies its
// cpu.max is the one that was asked for. The systemd path hands the work to
// another component, so "the quota is applied" is checked rather than assumed.
func (s *Slice) Confirm(pid int) error {
	if s == nil {
		return nil
	}
	// systemd applies the scope over D-Bus, so the move is not complete the
	// instant the process exists. Poll briefly rather than reading once and
	// declaring failure on a race — but keep it bounded, because "the quota
	// never arrived" has to stay a real, reportable outcome.
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := s.confirmOnce(pid)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (s *Slice) confirmOnce(pid int) error {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return fmt.Errorf("confirm cpu quota: %w", err)
	}
	path := ""
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			path = filepath.Join("/sys/fs/cgroup", strings.TrimSpace(rest))
			break
		}
	}
	if path == "" {
		return fmt.Errorf("confirm cpu quota: pid %d has no cgroup v2 entry", pid)
	}
	return s.confirmAt(path)
}

// confirmAt checks the cgroup a process actually landed in. A separate method
// because what it needs is a directory rather than a /proc entry, so it can be
// tested against an ordinary one.
//
// Path is adopted at the end and not before: Close removes whatever Path holds,
// so adopting a landing that then fails verification hands teardown a directory
// belonging to somebody else and leaves the slice we really made behind.
// Refusing the run is not enough on its own — the deferred Close still runs
// afterwards, and Path is what it reads.
func (s *Slice) confirmAt(path string) error {
	if err := underParent(path, s.parent, s.sliceUnit); err != nil {
		return err
	}
	if s.Percent > 0 {
		got, err := os.ReadFile(filepath.Join(path, "cpu.max"))
		if err != nil {
			return fmt.Errorf("confirm cpu quota: read %s/cpu.max: %w", path, err)
		}
		if want := cpuMaxLine(s.Percent); strings.TrimSpace(string(got)) != want {
			return fmt.Errorf("cpu quota not applied: %s/cpu.max is %q, expected %q",
				path, strings.TrimSpace(string(got)), want)
		}
	}
	if s.Weight > 0 {
		got, err := os.ReadFile(filepath.Join(path, "cpu.weight"))
		if err != nil {
			return fmt.Errorf("confirm cpu weight: read %s/cpu.weight: %w", path, err)
		}
		if want := cpuWeightLine(s.Weight); strings.TrimSpace(string(got)) != want {
			return fmt.Errorf("cpu weight not applied: %s/cpu.weight is %q, expected %q",
				path, strings.TrimSpace(string(got)), want)
		}
	}
	s.Path = path
	return nil
}

// underParent reports whether a process's cgroup is where this slice expected
// it to be. A free function so it can be tested without a cgroupfs.
//
// The two paths need different questions asked. On the direct path the slice
// directory *is* the target — its own for a single run, the team's for a member
// of one — so the landing place must be it or below it. Under systemd the
// process lands in a scope directory systemd made inside the slice, so the
// question is about the parent of where it landed.
func underParent(landed, parentDir, sliceUnit string) error {
	switch {
	case parentDir != "":
		if landed != parentDir && !strings.HasPrefix(landed, parentDir+"/") {
			return fmt.Errorf("cpu quota not applied: the process landed in %s, "+
				"which is not inside the slice %s it was meant to run in", landed, parentDir)
		}
	case sliceUnit != "":
		if got := filepath.Base(filepath.Dir(landed)); got != sliceUnit {
			return fmt.Errorf("cpu quota not applied: the process landed in %s, "+
				"whose parent is %s and not this team's slice %s", landed, got, sliceUnit)
		}
	}
	return nil
}
