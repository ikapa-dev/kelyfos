package sandbox

import (
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

// Slice is a cgroup v2 directory holding one sandbox's Firecracker process.
//
// It exists so `cpu_quota` can cap the CPU time a sandbox actually consumes,
// which is a different question from how many cores it can see (E1-2, and the
// distinction docs/resources.md spells out). The guest cannot influence it:
// this is a host-side control on the VMM process, which is the only place a
// limit on untrusted code is worth anything (F-D2).
//
// If PLAN.html's P4-1 jailer ever lands, the jailer takes this over — it
// creates cgroups itself. Until then this is standalone and deliberately small.
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

	// Where this slice is expected to live, when it lives under a team's.
	// parent is the absolute directory on the direct path; sliceUnit is the
	// systemd unit name on the other. Confirm checks the process landed there,
	// which matters most for a child with no quota of its own: without a
	// placement check there would be nothing left to verify, and Close would
	// then be holding a path nobody proved was ours.
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
		return sl, nil
	}

	sl.Path = filepath.Join(root, sl.name)
	if err := os.Mkdir(sl.Path, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create cgroup %s: %w", sl.Path, err)
	}
	if err := os.WriteFile(filepath.Join(sl.Path, "cpu.max"), []byte(cpuMaxLine(percent)), 0o644); err != nil {
		_ = os.Remove(sl.Path)
		return nil, fmt.Errorf("write cpu.max in %s: %w", sl.Path, err)
	}
	// The directory handle places the child in this cgroup at clone time.
	// Adding the pid afterwards would leave a window in which the process runs
	// uncapped, which for a quota is exactly the wrong window.
	dir, err := os.Open(sl.Path)
	if err != nil {
		_ = os.Remove(sl.Path)
		return nil, err
	}
	sl.dir = dir
	return sl, nil
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
	// Checked before Path is adopted, not after: Close removes whatever Path
	// holds, and a process that landed somewhere unexpected would otherwise
	// hand teardown a directory belonging to somebody else.
	if err := underParent(path, s.parent, s.sliceUnit); err != nil {
		return err
	}
	s.Path = path
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
	return nil
}

// underParent reports whether a process's cgroup is where this slice expected
// it to be. A free function so it can be tested without a cgroupfs.
//
// The two paths need different questions asked. On the direct path the slice
// directory *is* the target, so the landing place must be it or below it. Under
// systemd the process lands in a scope directory systemd made inside the slice,
// so the question is about the parent of where it landed.
func underParent(landed, parentDir, sliceUnit string) error {
	switch {
	case parentDir != "":
		if landed != parentDir && !strings.HasPrefix(landed, parentDir+"/") {
			return fmt.Errorf("cpu quota not applied: the process landed in %s, "+
				"which is not inside this team's slice %s", landed, parentDir)
		}
	case sliceUnit != "":
		if got := filepath.Base(filepath.Dir(landed)); got != sliceUnit {
			return fmt.Errorf("cpu quota not applied: the process landed in %s, "+
				"whose parent is %s and not this team's slice %s", landed, got, sliceUnit)
		}
	}
	return nil
}
