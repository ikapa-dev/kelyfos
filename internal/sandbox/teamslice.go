package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// TeamSlice is a team's collective CPU cap: one cgroup v2 slice per
// `kelyfos team up`, with every agent's E1-2 Slice as a child of it (E2-6).
//
// The hierarchy is the mechanism, not decoration. An agent may never exceed its
// own `cpu.max`, and the whole team may never exceed the parent's, and the
// kernel composes those two ceilings without the host doing any arithmetic —
// which is why the sum of the agents' quotas is deliberately allowed to exceed
// the team's (F-D21). `cpu.weight` on each child is what divides the parent's
// bandwidth when siblings actually contend.
//
// It is a separate type from Slice on purpose: nothing should be able to hand a
// whole team's cgroup to one Firecracker by putting it in Options.CPUSlice.
type TeamSlice struct {
	// Path is the parent cgroup directory. Known immediately on the direct
	// path; on the systemd path it is learned from where the first agent
	// actually landed, because systemd owns the layout there.
	Path    string
	Percent int

	unit string // systemd unit name, "kelyfos-team-<x>.slice"
	name string // directory name on the direct path, "kelyfos-team-<x>"
	mode mode
	root string // what pickMode chose, direct path only
	dir  *os.File

	// reverted records that a systemd runtime property was set and has to be
	// taken back at teardown, so a team's cap does not outlive the team.
	setProperty bool
}

// NewTeamSlice creates the parent. percent is the collective cap as a share of
// one core's CPU time, exactly as `cpu_quota` means everywhere else; zero means
// the team gets a shared home but no cap of its own, which is what a team with
// per-agent quotas and no [team.resources] asks for.
//
// instance is what makes this team's parent *this* team's — the caller passes
// its recorder session id (P7-16, D79). Before it, the parent was named for the
// team's name alone, and a name is what a person wrote in kelyfos.toml: two
// checkouts of one project running at once shared one cgroup. The systemd path
// made that a way to lose machines rather than only bookkeeping — the second
// team's set-property overwrote the first team's cap, and the second team's
// Close ran `systemctl --user stop` on the slice, which stops every scope in it,
// including the first team's Firecrackers. On the direct path the same name
// meant one directory: cpu.max rewritten under a running team, and a Close that
// either failed on a populated cgroup or removed the parent a live team was
// still accounted in.
//
// pickMode runs once here, for the whole team. That matters: five agents each
// deciding for themselves could disagree about the mode, and five agents in
// different places are not a hierarchy.
func NewTeamSlice(team, instance string, percent int) (*TeamSlice, error) {
	m, root, err := pickMode()
	if err != nil {
		return nil, err
	}
	name := teamSliceName(team, instance)
	t := &TeamSlice{Percent: percent, name: name, unit: name + ".slice", mode: m, root: root}

	if m == modeSystemd {
		if percent > 0 {
			if err := t.setSystemdQuota(); err != nil {
				return nil, err
			}
		}
		// With no cap there is nothing to ask systemd for: `--slice` on each
		// agent creates the slice, and every level above it, on its own.
		return t, nil
	}

	t.Path = filepath.Join(root, name)
	if err := os.Mkdir(t.Path, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create team cgroup %s: %w", t.Path, err)
	}
	// Written unconditionally, including when an interrupted run left the
	// directory behind: an adopted cgroup carrying a previous team's cap would
	// be a limit nobody in this run asked for.
	line := "max " + cpuMaxLineDenominator()
	if percent > 0 {
		line = cpuMaxLine(percent)
	}
	if err := os.WriteFile(filepath.Join(t.Path, "cpu.max"), []byte(line), 0o644); err != nil {
		_ = os.Remove(t.Path)
		return nil, fmt.Errorf("write cpu.max in %s: %w", t.Path, err)
	}
	// A fresh cgroup delegates nothing, so without this the children would be
	// directories with no cpu.max to write — the same failure a GitHub runner
	// produced one level up, and the reason delegatesCPU exists.
	if err := delegateCPU(t.Path); err != nil {
		_ = os.Remove(t.Path)
		return nil, fmt.Errorf("team cgroup %s: %w", t.Path, err)
	}
	dir, err := os.Open(t.Path)
	if err != nil {
		_ = os.Remove(t.Path)
		return nil, err
	}
	t.dir = dir
	return t, nil
}

// setSystemdQuota asks the user manager for the parent's cap *before any agent
// starts*, which is what makes this the whole team's ceiling rather than a
// ceiling that arrives late.
//
// The alternative — creating the slice by starting the first agent into it and
// then writing its cpu.max ourselves — was measured and rejected: systemd
// applies the unit's own properties when it materialises the slice, so a value
// written into a directory systemd has not started yet is discarded. Asking
// systemd is also what F-D11 already decided for the leaf, for the same reason:
// the user manager is the component that legitimately holds this.
func (t *TeamSlice) setSystemdQuota() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("a team cpu_quota needs systemctl to set it on the team's slice, and it is not "+
			"on PATH.\n"+
			"    Run as root, set KELYFOS_CGROUP_ROOT to a delegated cgroup, or drop "+
			"[team.resources] cpu_quota. (%w)", err)
	}
	out, err := exec.Command("systemctl", "--user", "set-property", "--runtime",
		t.unit, fmt.Sprintf("CPUQuota=%d%%", t.Percent)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set the team's collective cap on %s: %w: %s",
			t.unit, err, strings.TrimSpace(string(out)))
	}
	t.setProperty = true
	return nil
}

// Agent creates one member's slice as a child of this one.
//
// Every agent gets a child, including one that declared no cpu_quota: being
// inside the collective cap is the point, and a child with no cpu.max of its
// own is exactly "bounded only by the team".
func (t *TeamSlice) Agent(id string, percent, weight int) (*Slice, error) {
	if t == nil {
		return NewCPUSlice(id, percent)
	}
	sl := &Slice{Percent: percent, Weight: weight, name: "kelyfos-" + id, mode: t.mode}
	if t.mode == modeSystemd {
		sl.sliceUnit = t.unit
		return sl, nil
	}

	sl.parent = t.Path
	sl.Path = filepath.Join(t.Path, sl.name)
	if err := os.Mkdir(sl.Path, 0o755); err != nil && !os.IsExist(err) {
		return nil, fmt.Errorf("create cgroup %s: %w", sl.Path, err)
	}
	if percent > 0 {
		if err := os.WriteFile(filepath.Join(sl.Path, "cpu.max"), []byte(cpuMaxLine(percent)), 0o644); err != nil {
			_ = os.Remove(sl.Path)
			return nil, fmt.Errorf("write cpu.max in %s: %w", sl.Path, err)
		}
	}
	if weight > 0 {
		if err := os.WriteFile(filepath.Join(sl.Path, "cpu.weight"), []byte(cpuWeightLine(weight)), 0o644); err != nil {
			_ = os.Remove(sl.Path)
			return nil, fmt.Errorf("write cpu.weight in %s: %w", sl.Path, err)
		}
	}
	dir, err := os.Open(sl.Path)
	if err != nil {
		_ = os.Remove(sl.Path)
		return nil, err
	}
	sl.dir = dir
	return sl, nil
}

// Resolve learns the parent's directory from where a child actually landed.
// Only the systemd path needs it: systemd owns the layout there, so the honest
// way to know the parent is to look at a child rather than to predict it.
func (t *TeamSlice) Resolve(childPath string) {
	if t == nil || t.Path != "" || childPath == "" {
		return
	}
	parent := filepath.Dir(childPath)
	if filepath.Base(parent) == t.unit {
		t.Path = parent
	}
}

// Confirm reads the collective cap back rather than trusting that asking for it
// worked — the same stance F-D11 takes about the per-sandbox quota.
func (t *TeamSlice) Confirm() error {
	if t == nil || t.Percent <= 0 {
		return nil
	}
	if t.Path == "" {
		return fmt.Errorf("the team's collective cap of %d%% could not be confirmed: "+
			"no agent landed in %s", t.Percent, t.unit)
	}
	got, err := os.ReadFile(filepath.Join(t.Path, "cpu.max"))
	if err != nil {
		return fmt.Errorf("confirm the team's cpu quota: read %s/cpu.max: %w", t.Path, err)
	}
	if want := cpuMaxLine(t.Percent); strings.TrimSpace(string(got)) != want {
		return fmt.Errorf("the team's collective cap was not applied: %s/cpu.max is %q, expected %q",
			t.Path, strings.TrimSpace(string(got)), want)
	}
	return nil
}

// CPUStat is the team's collective consumption — the number the E2 acceptance
// test measures. It is the parent's own accounting, which includes every child,
// so it cannot disagree with the sum of the agents.
func (t *TeamSlice) CPUStat() (map[string]int64, error) {
	if t == nil {
		return nil, fmt.Errorf("no team slice")
	}
	return CPUStatAt(t.Path)
}

// Close takes the parent away, after every child is gone.
//
// It returns its error, unlike Slice.Close, because the failure mode here is
// silent: rmdir refuses a populated cgroup, so a teardown in the wrong order
// leaves one directory per run and says nothing at all.
func (t *TeamSlice) Close() error {
	if t == nil {
		return nil
	}
	if t.mode == modeSystemd {
		// systemd removes the scopes when their processes exit; what does not go
		// on its own is the runtime property, which would otherwise still be
		// capping a slice the next team of the same name lands in.
		if t.setProperty {
			if out, err := exec.Command("systemctl", "--user", "revert", "--runtime", t.unit).CombinedOutput(); err != nil {
				return fmt.Errorf("take back the team's cap on %s: %w: %s",
					t.unit, err, strings.TrimSpace(string(out)))
			}
		}
		// And the slice itself is stopped rather than left for systemd to
		// collect whenever it gets to it. A lingering empty slice is not
		// harmless: a cgroup's counters are cumulative for the life of the
		// *directory*, so the next team of the same name would land in a parent
		// already holding the previous team's CPU time — and a reader comparing
		// that parent against its fresh children would find they did not add up.
		// Measured exactly that way before this call existed.
		if out, err := exec.Command("systemctl", "--user", "stop", t.unit).CombinedOutput(); err != nil {
			return fmt.Errorf("stop the team's slice %s: %w: %s",
				t.unit, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if t.dir != nil {
		_ = t.dir.Close()
	}
	if t.Path == "" {
		return nil
	}
	if err := os.Remove(t.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove the team cgroup %s: %w", t.Path, err)
	}
	return nil
}

// Unit is the systemd slice this team's scopes are placed in, or "" on the
// direct path.
func (t *TeamSlice) Unit() string {
	if t == nil || t.mode != modeSystemd {
		return ""
	}
	return t.unit
}

// teamSliceName turns a team's name and this run of it into exactly one systemd
// hierarchy component.
//
// The dash is systemd's separator: a-b-c.slice lives at a.slice/a-b.slice/
// a-b-c.slice. So "kelyfos-team-<name>" is a deliberate three-level tree with
// every KelyfOS team under one root — and a team called "foo-bar" would
// silently add a fourth level and change what the cap applies to. Mapping
// everything outside [A-Za-z0-9_] to _ keeps the team's own name one component,
// whatever the user called it. Same string names the directory on the direct
// path, because one spelling in one place cannot disagree with itself.
//
// The instance is appended with "_", which is the one joiner that survives the
// mapping above and is not systemd's separator, so two teams of one name get
// two parents and neither can stop, re-cap or remove the other's (P7-16, D79).
// It is truncated to eight characters: the whole point is to tell two
// simultaneous teams apart, and eight hex characters of a session id is already
// how this project names a sandbox. The team's own name is truncated first and
// separately, so a long name can never crowd the instance out — the name is a
// label and the instance is what makes the cgroup correct.
func teamSliceName(team, instance string) string {
	one := func(s string) string {
		var b strings.Builder
		for _, r := range s {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
				b.WriteRune(r)
			default:
				b.WriteByte('_')
			}
		}
		return b.String()
	}
	name := one(team)
	if name == "" {
		name = "unnamed"
	}
	// systemd unit names are bounded; a long team name is truncated rather than
	// refused, because the name is the user's label and the cgroup is ours.
	if len(name) > 64 {
		name = name[:64]
	}
	key := one(instance)
	if len(key) > 8 {
		key = key[:8]
	}
	if key == "" {
		// Nothing to tell this team apart by. Keeping the old, shared name here
		// would put a caller that passed nothing back in the collision this
		// exists to close, so it gets a parent of its own that no other team
		// will pick: a cgroup is per-process machinery and the pid is the one
		// thing every caller has.
		key = strconv.Itoa(os.Getpid())
	}
	return "kelyfos-team-" + name + "_" + key
}

// cpuMaxLineDenominator is the period half of a cpu.max line, so "no cap" can
// be written in the same shape as a cap without a second copy of the number.
func cpuMaxLineDenominator() string {
	_, period, _ := strings.Cut(cpuMaxLine(100), " ")
	return period
}
