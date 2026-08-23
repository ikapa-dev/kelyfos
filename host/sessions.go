package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// Named sessions: pause, resume, sessions (E5-1, docs/qol.md §1).
//
// A paused session is a snapshot plus the two things a snapshot does not carry
// and a resume needs: the policy the machine was running under, and the name a
// person chose for it. Everything else is P3-1's snapshot layer unchanged —
// pause is `snapshot save` plus a teardown plus two files, not a second
// mechanism for the same thing.

func namedDir(name string) string { return filepath.Join(sandbox.Root(), "named", name) }

// namedPolicy and namedMeta are the two files a named session adds to what
// `snapshot save` already writes.
func namedPolicy(dir string) string { return filepath.Join(dir, config.FileName) }
func namedMeta(dir string) string   { return filepath.Join(dir, "named.json") }

// NamedMeta is what a pause knows and a resume needs, beyond the machine.
type NamedMeta struct {
	Name     string    `json:"name"`
	Sandbox  string    `json:"sandbox"`
	Session  string    `json:"session"`
	PausedAt time.Time `json:"paused_at"`
	Kelyfos  string    `json:"kelyfos"`
	// PolicyPath is where the frozen policy came from, so a resume can say
	// which file it is comparing against rather than assuming the working
	// directory holds the same project.
	PolicyPath string `json:"policy_path,omitempty"`
}

func readNamedMeta(dir string) (*NamedMeta, error) {
	blob, err := os.ReadFile(namedMeta(dir))
	if err != nil {
		return nil, err
	}
	var m NamedMeta
	if err := json.Unmarshal(blob, &m); err != nil {
		return nil, fmt.Errorf("the session's metadata is unreadable: %w", err)
	}
	return &m, nil
}

// validSessionName is snapshot's rule, and for the same reason: a name becomes
// a directory. It is applied here even though a person types this one, because
// `pause --as ../../etc` is a thing a script can do just as easily.
func validSessionName(name string) error {
	if name == "" {
		return errors.New("a paused session needs a name: --as <name>")
	}
	return validSnapshotName(name)
}

// --- kelyfos pause -----------------------------------------------------------

func pauseCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos pause", flag.ExitOnError)
	var (
		id   = fs.String("sandbox", "", "sandbox id (default: the only running one)")
		name = fs.String("as", "", "name to store the paused session under")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos pause --as <name> [flags]

Freezes a running sandbox under a name and stops it, so `+"`kelyfos resume <name>`"+`
brings back the same machine — the same memory, the same disks, and the same
policy it was running under.

The policy is frozen deliberately. A resumed machine is the *same* machine, and
its memory holds an environment built under the old policy; running it under a
new one produces a guest that no longer works rather than a guest that obeys.
`+"`resume`"+` says so, and names what changed.

The workspace is NOT written back here. A pause is a machine you mean to come
back to, and writing to the host directory at that moment changes it under
somebody who did not ask. It travels with the session and is written back when
the session finally ends.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if err := validSessionName(*name); err != nil {
		return err
	}

	st, err := sandbox.Load(*id)
	if err != nil {
		return err
	}
	dir := namedDir(*name)
	if _, err := os.Stat(namedMeta(dir)); err == nil {
		return fmt.Errorf("a session called %q is already stored (%s). Remove it with "+
			"`kelyfos sessions rm %s`, or choose another name", *name, dir, *name)
	}

	// The marker goes down before the machine does, so the process that owns
	// this sandbox cannot wake up, find it stopping, and write the workspace
	// back before it learns that this was a pause (docs/qol.md §1.3).
	if err := os.WriteFile(sandbox.PauseMarker(st), []byte(*name+"\n"), 0o600); err != nil {
		return fmt.Errorf("mark the sandbox as pausing: %w", err)
	}
	paused := false
	defer func() {
		if !paused {
			// A pause that failed leaves a running machine, and a machine that
			// still thinks it is pausing would skip its sync-back for ever.
			_ = os.Remove(sandbox.PauseMarker(st))
		}
	}()

	started := time.Now()
	statePath, memPath, err := sandbox.SnapshotRunning(st, dir)
	if err != nil {
		return err
	}

	// The policy, frozen. Read from where this sandbox's own run was launched
	// rather than from here, so pausing from another directory does not freeze
	// a different project's file.
	meta := NamedMeta{Name: *name, Sandbox: st.ID, Session: st.RecordSession(),
		PausedAt: time.Now(), Kelyfos: Version}
	if cfg, err := loadPolicy(); err == nil && cfg != nil {
		blob, err := os.ReadFile(cfg.Path)
		if err != nil {
			return fmt.Errorf("freeze the policy: %w", err)
		}
		if err := os.WriteFile(namedPolicy(dir), blob, 0o600); err != nil {
			return err
		}
		meta.PolicyPath = cfg.Path
	}
	blob, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(namedMeta(dir), append(blob, '\n'), 0o600); err != nil {
		return err
	}

	stateInfo, _ := os.Stat(statePath)
	memInfo, _ := os.Stat(memPath)
	fmt.Printf("paused %s as %q in %d ms\n", st.ID, *name, time.Since(started).Milliseconds())
	fmt.Printf("  stored   %s (%s)\n", dir, report.HumanKiB(dirKiB(dir)))
	fmt.Printf("  memory   %s state · %s\n",
		report.HumanKiB(sizeOf(memInfo)/1024), report.HumanKiB(sizeOf(stateInfo)/1024))
	if meta.PolicyPath != "" {
		fmt.Printf("  policy   frozen from %s\n", meta.PolicyPath)
	} else {
		fmt.Printf("  policy   none found; the resume has no ceiling to restore\n")
	}
	if st.Workspace != "" {
		fmt.Printf("  workspace travels with the session; it is written back when this session ends\n")
	}
	fmt.Printf("\nresume it with:  kelyfos resume %s\n", *name)

	// Stopped last, so a failure above leaves a running machine rather than a
	// stopped machine and half a stored session. The process that owns this
	// sandbox does the actual teardown; this asks the guest to go.
	paused = true
	if err := sandbox.RequestShutdown(st, 20*time.Second); err != nil {
		return fmt.Errorf("the session is stored at %s, but the sandbox did not stop: %w", dir, err)
	}
	return nil
}

// --- kelyfos sessions --------------------------------------------------------

func sessionsCmd(argv []string) error {
	if len(argv) > 0 && argv[0] == "rm" {
		return sessionsRemove(argv[1:])
	}
	fs := flag.NewFlagSet("kelyfos sessions", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos sessions [rm <name>]

Lists the paused sessions this machine is holding, with what each one costs on
disk. A paused session holds its workspace inside it, which is why the size is
in the listing rather than somewhere you have to go and look.

`)
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	entries, err := os.ReadDir(filepath.Join(sandbox.Root(), "named"))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no paused sessions")
		return nil
	}
	if err != nil {
		return err
	}
	type row struct {
		name, age, size, policy string
		at                      time.Time
	}
	var rows []row
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := namedDir(e.Name())
		meta, err := readNamedMeta(dir)
		if err != nil {
			continue
		}
		policy := "none"
		if meta.PolicyPath != "" {
			policy = "frozen"
		}
		rows = append(rows, row{
			name: meta.Name, at: meta.PausedAt, policy: policy,
			age:  time.Since(meta.PausedAt).Truncate(time.Second).String(),
			size: report.HumanKiB(dirKiB(dir)),
		})
	}
	if len(rows) == 0 {
		fmt.Println("no paused sessions")
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].at.After(rows[j].at) })
	fmt.Printf("%-24s %-12s %-10s %s\n", "NAME", "AGE", "SIZE", "POLICY")
	for _, r := range rows {
		fmt.Printf("%-24s %-12s %-10s %s\n", r.name, r.age, r.size, r.policy)
	}
	return nil
}

func sessionsRemove(argv []string) error {
	if len(argv) == 0 {
		return errors.New("usage: kelyfos sessions rm <name>")
	}
	name := argv[0]
	if err := validSessionName(name); err != nil {
		return err
	}
	dir := namedDir(name)
	meta, err := readNamedMeta(dir)
	if err != nil {
		return fmt.Errorf("no paused session called %q", name)
	}
	size := report.HumanKiB(dirKiB(dir))
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	// What is being discarded is said, because a paused session holds a
	// workspace and "removed" is a thinner sentence than it sounds.
	fmt.Printf("removed %q — %s, paused %s ago\n",
		name, size, time.Since(meta.PausedAt).Truncate(time.Second))
	return nil
}

// dirKiB is the size of a stored session, in KiB so it can go through the same
// humaniser every other size in this product uses.
func dirKiB(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total / 1024
}

// policyDifference describes what changed between the frozen policy and the one
// in force now, in the terms a person would use.
//
// Not a diff of the files: a reordered key or a new comment is not a change to
// what the machine may do. This compares the parsed values that actually bound
// a sandbox, so what it prints is what somebody would care about.
func policyDifference(frozen, current *config.Config) []string {
	if frozen == nil || current == nil {
		return nil
	}
	var out []string
	num := func(label string, was, now int) {
		if was != now {
			out = append(out, fmt.Sprintf("%s %d → %d", label, was, now))
		}
	}
	num("[resources] cpus", frozen.ResCPUs, current.ResCPUs)
	num("[resources] mem (MiB)", frozen.ResMemMiB, current.ResMemMiB)
	num("[resources] cpu_quota (%)", frozen.ResCPUQuota, current.ResCPUQuota)
	if frozen.Image != current.Image {
		out = append(out, fmt.Sprintf("image %q → %q", frozen.Image, current.Image))
	}
	gained, lost := listDiff(frozen.Allow, current.Allow)
	if len(gained) > 0 {
		out = append(out, "allow gained "+strings.Join(gained, ", "))
	}
	if len(lost) > 0 {
		out = append(out, "allow lost "+strings.Join(lost, ", "))
	}
	return out
}

func listDiff(was, now []string) (gained, lost []string) {
	inWas := map[string]bool{}
	for _, v := range was {
		inWas[v] = true
	}
	inNow := map[string]bool{}
	for _, v := range now {
		inNow[v] = true
		if !inWas[v] {
			gained = append(gained, v)
		}
	}
	for _, v := range was {
		if !inNow[v] {
			lost = append(lost, v)
		}
	}
	sort.Strings(gained)
	sort.Strings(lost)
	return gained, lost
}
