package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
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
	// WorkspaceHost is the directory this machine's workspace was packed from.
	// The pause is the last process that knows it, and the resume is the one
	// that owes the write-back.
	WorkspaceHost string `json:"workspace_host,omitempty"`
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
		PausedAt: time.Now(), Kelyfos: Version, WorkspaceHost: st.WorkspaceHost}
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

	// Into the machine's own chain, and the chain is not closed: this session is
	// coming back, and a session.end would make `--verify` describe a machine
	// that still exists as finished (docs/qol.md §1.4).
	if rec, err := recorder.Open(sandbox.Root(), st.RecordSession()); err == nil {
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionPause, Name: *name,
			DurationMS: time.Since(started).Milliseconds()})
		_ = rec.Close()
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

// --- kelyfos resume ----------------------------------------------------------

func resumeCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos resume", flag.ExitOnError)
	var (
		console = fs.Bool("console", false, "stream the guest serial console")
		noSync  = fs.Bool("no-sync-back", false, "leave the workspace image alone at the end")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos resume <name> [flags]

Brings back a paused session: the same memory, the same disks, and the policy it
was paused under. If this project's kelyfos.toml has changed since, the resume
says what changed and runs under the frozen copy anyway — the machine's memory
was built under that one, and a guest whose proxy address no longer exists is
not a machine obeying the new policy, it is a broken machine.

The workspace, if there was one, is written back when this run ends. That is the
final shutdown the pause deferred.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kelyfos resume <name>")
	}
	name := fs.Arg(0)
	if err := validSessionName(name); err != nil {
		return err
	}
	dir := namedDir(name)
	meta, err := readNamedMeta(dir)
	if err != nil {
		return fmt.Errorf("no paused session called %q — `kelyfos sessions` lists them", name)
	}
	snapMeta, err := sandbox.ReadSnapshotMeta(dir)
	if err != nil {
		return fmt.Errorf("session %q is incomplete: %w", name, err)
	}

	// The frozen policy, and what it says about the one in force now.
	frozen, err := frozenPolicy(dir)
	if err != nil {
		return err
	}
	current, _ := loadPolicy()
	var differences []string
	if frozen != nil {
		differences = policyDifference(frozen, current)
		if diffs := differences; len(diffs) > 0 {
			fmt.Printf("kelyfos: this session was paused under a %s that has since changed.\n", config.FileName)
			fmt.Printf("    Resuming under the frozen copy, which is what the machine's memory expects.\n")
			fmt.Printf("    %d difference(s): %s\n", len(diffs), strings.Join(diffs, ", "))
			fmt.Printf("    To run under the current policy, start a new sandbox rather than resuming.\n\n")
		}
		// The frozen policy is what the machine runs under; it is not a way
		// past the ceiling in force now. Same rule sandbox_restore follows, and
		// the hole E4-2 found there is not being dug again here (F-D39).
		if err := frozenFitsCurrent(name, frozen, current); err != nil {
			return err
		}
	}

	// The resumed machine records into the session it was paused from, so one
	// chain covers the whole life of the machine rather than one per resume.
	// "It is the same session" is a claim this is what makes true.
	opts := sandbox.Options{Arch: snapMeta.Arch, Flavor: snapMeta.Flavor, Quiet: true,
		VcpuCount: snapMeta.VcpuCount, MemMiB: snapMeta.MemMiB, Session: meta.Session}
	if opts.Arch == "" {
		opts.Arch = sandbox.HostArch()
	}
	if *console {
		opts.Console = prefixWriter{os.Stderr, "[guest] "}
	}
	if snapMeta.HasNetwork {
		return fmt.Errorf("session %q was paused from a sandbox with egress, and resuming one is "+
			"the same problem restoring one is: the guest's address is inside its memory image "+
			"and something else may hold it now (D22).\n"+
			"    bring it back with:  kelyfos snapshot restore -name %s",
			name, name)
	}

	sb, elapsed, err := sandbox.Restore(dir, opts)
	if err != nil {
		return err
	}
	// The sync-back is registered FIRST so it runs LAST: defers unwind
	// last-registered-first, and the workspace has to be written back after the
	// guest has stopped, not before. A guest still running has pages of that
	// disk in its own cache, and copying the image out from under it produces a
	// directory missing exactly the files somebody just wrote — which is what
	// the first live run of this did.
	if snapMeta.HasWorkspace && meta.WorkspaceHost != "" && !*noSync {
		defer syncResumedWorkspace(sb, meta.WorkspaceHost)
	}
	defer func() {
		if err := sb.Shutdown(10 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
	}()

	if rec, err := recorder.Open(sandbox.Root(), meta.Session); err == nil {
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionResume, Name: name,
			BootMS: elapsed.Milliseconds(), Reason: strings.Join(differences, ", ")})
		_ = rec.Close()
	}

	fmt.Printf("resumed %q in %d ms (paused %s ago)\n", name, elapsed.Milliseconds(),
		time.Since(meta.PausedAt).Truncate(time.Second))
	fmt.Printf("  sandbox  %s\n", sb.State.ID)
	fmt.Printf("  vsock    %s\n", sb.State.UDSPath)
	if meta.PolicyPath != "" {
		fmt.Printf("  policy   frozen copy from %s\n", meta.PolicyPath)
	}

	fmt.Println("\nCtrl-C to stop.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	vmExited := make(chan struct{})
	go func() { _ = sb.Wait(); close(vmExited) }()
	select {
	case <-ctx.Done():
		fmt.Println("\nstopping...")
		return nil
	case <-vmExited:
		return errors.New("the resumed microVM exited unexpectedly")
	}
}

// frozenPolicy parses the policy stored beside a paused session, or returns nil
// when the pause found none to freeze.
func frozenPolicy(dir string) (*config.Config, error) {
	path := namedPolicy(dir)
	if _, err := os.Stat(path); err != nil {
		return nil, nil
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("the frozen policy does not parse: %w", err)
	}
	return cfg, nil
}

// frozenFitsCurrent refuses a resume whose frozen policy asks for more than the
// project allows now. A paused machine is not a way to carry an old ceiling
// forward past a new one.
func frozenFitsCurrent(name string, frozen, current *config.Config) error {
	if current == nil {
		return nil
	}
	if current.ResCPUs > 0 && frozen.ResCPUs > current.ResCPUs {
		line, _ := current.Ceiling("cpus")
		return denial.CeilingResume.Err(denial.V{
			"name": name, "key": "cpus", "frozen": strconv.Itoa(frozen.ResCPUs),
			"limit": strconv.Itoa(current.ResCPUs), "file": current.Path,
			"line": strconv.Itoa(line)})
	}
	if current.ResMemMiB > 0 && frozen.ResMemMiB > current.ResMemMiB {
		line, _ := current.Ceiling("mem")
		return denial.CeilingResume.Err(denial.V{
			"name": name, "key": "mem", "frozen": fmt.Sprintf("%d MiB", frozen.ResMemMiB),
			"limit": fmt.Sprintf("%d MiB", current.ResMemMiB), "file": current.Path,
			"line": strconv.Itoa(line)})
	}
	for _, d := range frozen.Allow {
		if !containsDomain(current.Allow, d) {
			return denial.AllowResume.Err(denial.V{
				"name": name, "domain": d, "file": current.Path})
		}
	}
	return nil
}

func syncResumedWorkspace(sb *sandbox.Sandbox, hostDir string) {
	image := sb.State.Workspace
	if image == "" {
		return
	}
	defer os.Remove(image)
	ws := sandbox.AdoptWorkspace(hostDir, image)
	dest, diverted, err := ws.SyncBack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kelyfos: workspace sync-back failed: %v\n", err)
		return
	}
	if diverted {
		fmt.Printf("\nthe host directory changed while this session was paused, so it was NOT "+
			"overwritten.\nresults written to %s instead\n", dest)
		return
	}
	fmt.Printf("workspace written back to %s\n", dest)
}
