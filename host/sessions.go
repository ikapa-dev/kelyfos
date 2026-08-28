package main

import (
	"bytes"
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
	// Before anything is written and before the machine is asked to stop,
	// because this is the one thing a pause can learn too late to act on.
	if err := refuseEgressPause(st, *name); err != nil {
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

// refuseEgressPause is the check pause owes the resume, made at the only moment
// it is still free to make: `resume` refuses every session whose snapshot has a
// NIC recorded, and the snapshot layer records one for every machine that had a
// TAP — so the machines this refuses are exactly the machines a pause could
// store and nothing could ever bring back.
//
// Met at the resume instead, it is met too late in both directions. The machine
// is already stopped, and the session it left behind is not something `snapshot
// restore` can open either: that command reads snapshots/<name> and a paused
// session lives in named/<name>. A refusal costs the user a pause they can take
// another way; the alternative costs them the machine.
//
// What it points at is the path that does work for egress, and it works because
// the snapshot carries the allowlist and the addressing with it: `snapshot save`
// freezes the machine without stopping it, and `snapshot restore` builds a
// network for the guest to come back into (D22).
func refuseEgressPause(st *sandbox.State, name string) error {
	if st.TAP == "" {
		return nil
	}
	// A TAP exists only where an allowlist did, so the empty case is a machine
	// whose state file predates one being recorded rather than a machine with a
	// NIC and no rules.
	allowed := "none recorded"
	if len(st.Allow) > 0 {
		allowed = strings.Join(st.Allow, ", ")
	}
	return fmt.Errorf("sandbox %s has egress (allowed: %s), and a paused session with a NIC is "+
		"one `kelyfos resume` refuses: the guest's address is inside its memory image and "+
		"something else may hold it by the time it comes back (D22).\n"+
		"    Nothing was stored and the sandbox is still running. Freeze it this way instead, "+
		"which restores into a network of its own:\n"+
		"      kelyfos snapshot save    -name %s   (the sandbox keeps running)\n"+
		"      kelyfos snapshot restore -name %s",
		st.ID, allowed, name, name)
}

// --- kelyfos sessions --------------------------------------------------------

func sessionsCmd(argv []string) error {
	if len(argv) > 0 {
		switch argv[0] {
		case "rm":
			return sessionsRemove(argv[1:])
		case "prune":
			return sessionsPrune(argv[1:])
		case "erase":
			return sessionsErase(argv[1:])
		}
	}
	fs := flag.NewFlagSet("kelyfos sessions", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos sessions [rm <name>] [prune] [erase <id>]

Lists the paused sessions this machine is holding, with what each one costs on
disk. A paused session holds its workspace inside it, which is why the size is
in the listing rather than somewhere you have to go and look.

rm discards a paused session. prune deletes recorded sessions (the flight
recorder's own history under ~/.cache/kelyfos/sessions/) older than the
retention floor — see 'kelyfos sessions prune -h'. erase rewrites one
recorded session's content fields to a fingerprint in place, without
deleting the session — see 'kelyfos sessions erase -h'.

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

// --- kelyfos sessions prune (P7-5, D61) --------------------------------------

// defaultRetentionDays is the floor kelyfos sessions prune applies when
// neither a policy file nor an explicit [sessions] retention_days key says
// otherwise — six months, the EU AI Act's own floor for a general-purpose
// system's records (D61's own rationale).
const defaultRetentionDays = 180

// retentionFloor turns [sessions] retention_days into the duration prune
// actually compares ages against. cfg may be nil (no policy file found),
// and cfg.Sessions may be nil (a policy with no [sessions] section) — both
// get the built-in default, the same way an absent retention_days key does
// (config.Sessions's own doc comment).
func retentionFloor(cfg *config.Config) time.Duration {
	days := defaultRetentionDays
	if cfg != nil && cfg.Sessions != nil && cfg.Sessions.RetentionDays > 0 {
		days = cfg.Sessions.RetentionDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// livePausedSessions is the set of recorder session ids a currently paused
// session still needs. A pause's own metadata (NamedMeta.Session) names the
// chain a later resume writes session.resume into — "one chain covers the
// whole life of the machine rather than one per resume" — so pruning that
// chain out from under a pause would either break the resume or make it
// silently start a fresh one. Checked by kelyfos sessions prune and erase
// alike, so neither can touch a session the other half of this file still
// considers alive.
func livePausedSessions() (map[string]bool, error) {
	live := map[string]bool{}
	entries, err := os.ReadDir(filepath.Join(sandbox.Root(), "named"))
	if errors.Is(err, os.ErrNotExist) {
		return live, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		meta, err := readNamedMeta(namedDir(e.Name()))
		if err != nil {
			continue
		}
		if meta.Session != "" {
			live[meta.Session] = true
		}
	}
	return live, nil
}

// hasLiveRunDir reports whether id has a run directory at all — the
// jailer's own chroot, created the moment a sandbox is asked to boot and
// removed on a clean teardown. A leftover one after a crash is a false
// positive prune/erase would rather have than the alternative: touching a
// session something might still be writing to.
func hasLiveRunDir(id string) bool {
	_, err := os.Stat(sandbox.RunDirOf(id))
	return err == nil
}

// sessionIsLive is prune's single skip-or-not question, combining all three
// guards erase asks separately (and reports separately, since a paused
// session and a possibly-running one call for different advice).
//
// P7-13: hasLiveRunDir alone only sees a sandbox whose own id names its run
// directory. A team's chain and a `kelyfos serve-mcp` process's own audit
// chain are both opened under an id sandbox.NewID() mints that is never any
// sandbox's own id, so no run directory is ever named for either — prune
// could delete one out from under a writer still appending to it, the same
// B1 gap erase's own review already found and closed for erase, left open
// here. running is sandbox.RunningSessions(), computed once by the caller
// rather than per session.
func sessionIsLive(id string, live, running map[string]bool) bool {
	return live[id] || hasLiveRunDir(id) || running[id]
}

// pruneEligible is prune's own age question, split out from the directory
// walk so it can be tested without a filesystem: a session is eligible once
// it has gone untouched for at least the retention floor, measured from
// events.jsonl's own mtime rather than from a session.end timestamp inside
// its chain — cheap (no chain has to be parsed to decide what to prune),
// and it treats a cleanly closed session and an orphaned/crashed one the
// same way, where the chain's own session.end may not exist for the second
// kind at all (docs/events.md: "a session that is still running has no
// session.end... the chain cannot tell those apart").
//
// events.jsonl's own mtime, not the session DIRECTORY's (S2): appending to
// an existing file does not advance its parent directory's own mtime on
// POSIX — only creating or removing an entry inside that directory does —
// so ageing by the directory aged a session from when its directory was
// first created (session START) while docs/retention.md described "twelve
// months from session close." events.jsonl is the one file every write to
// this session touches, including the last one, so its own mtime is
// genuinely last-write with the same no-chain-parse cost pruneTemplates'
// own mtime-based aging already accepts for the fork-template cache. One
// consequence worth being explicit about, not a defect: kelyfos sessions
// erase also writes events.jsonl, so an Article 17 erasure resets this
// clock the same way any other write to the chain would — consistent with
// "age since last write," not an exception to it.
func pruneEligible(mtime, now time.Time, floor time.Duration) bool {
	return now.Sub(mtime) >= floor
}

func sessionsPrune(argv []string) error {
	fs := flag.NewFlagSet("kelyfos sessions prune", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "report what would be pruned without deleting anything")
	policyPath := fs.String("policy", "",
		"the kelyfos.toml whose [sessions] retention_days applies (default: the nearest one, found by walking up)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos sessions prune [-dry-run] [-policy <file>]

Deletes recorded sessions under ~/.cache/kelyfos/sessions/ that are older
than the retention floor — [sessions] retention_days in kelyfos.toml, or 180
days (six months, the EU AI Act's own floor for a general-purpose system)
when no policy sets one. A session younger than the floor is never touched,
however this is invoked: the floor is a minimum, not a target.

A session still paused (kelyfos pause) or with a run directory that looks
live is skipped, however old it is — deleting either would break a resume
or race a process still writing to it.

Whole directories, not surgical edits: this deletes what the retention
floor no longer requires keeping. To remove specific content from a session
you still need to keep, see 'kelyfos sessions erase'.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	cfg, cfgErr := loadPolicyAt(*policyPath)
	if cfgErr != nil {
		return cfgErr
	}
	if cfg != nil {
		fmt.Printf("policy: %s\n", cfg.Path)
	}
	floor := retentionFloor(cfg)
	fmt.Printf("retention floor: %.0f day(s)\n", floor.Hours()/24)

	live, err := livePausedSessions()
	if err != nil {
		return err
	}
	running, err := sandbox.RunningSessions()
	if err != nil {
		return err
	}

	root := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("no recorded sessions")
		return nil
	}
	if err != nil {
		return err
	}

	now := time.Now()
	var prunedN int
	var prunedKiB int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if sessionIsLive(id, live, running) {
			continue
		}
		// events.jsonl's own mtime, not the directory's own (S2) — see
		// pruneEligible's comment for why: appending never advances a
		// directory's own mtime on POSIX, only creating or removing an
		// entry inside it does, so this is what makes "age" mean "since
		// last write" rather than "since the session started." root here
		// is already recorder.SessionsDir(sandbox.Root()), so the file is
		// joined directly rather than through recorder.Path (which itself
		// appends "sessions").
		info, err := os.Stat(filepath.Join(root, id, "events.jsonl"))
		if err != nil {
			continue
		}
		if !pruneEligible(info.ModTime(), now, floor) {
			continue
		}
		age := now.Sub(info.ModTime())
		dir := filepath.Join(root, id)
		size := dirKiB(dir)
		verb := "pruned "
		if *dryRun {
			verb = "would prune"
		} else if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: could not prune %s: %v\n", id, err)
			continue
		}
		fmt.Printf("%s  %s  %s old, %s\n", verb, id, age.Truncate(time.Hour), report.HumanKiB(size))
		prunedN++
		prunedKiB += size
	}
	if prunedN == 0 {
		fmt.Println("nothing eligible — every recorded session is inside the retention floor")
		return nil
	}
	verb := "pruned"
	if *dryRun {
		verb = "would prune"
	}
	fmt.Printf("%s %d session(s), %s\n", verb, prunedN, report.HumanKiB(prunedKiB))
	return nil
}

// --- kelyfos sessions erase (P7-5, D61) --------------------------------------

func sessionsErase(argv []string) error {
	fs := flag.NewFlagSet("kelyfos sessions erase", flag.ExitOnError)
	reason := fs.String("reason", "", "why — recorded in the session.erasure event this writes (required)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos sessions erase -reason "<why>" <id>

Rewrites one recorded session's own chain in place: every field known to
carry guest-influenced or operator-supplied content — command output, a
file path, a connection's peer, an MCP call's argument summary and tool
name, a command's own argv, the host's own argv (what a trailing
"-- <command>" carries, e.g. kelyfos run -- claude "...") and more — is
replaced with a fingerprint of what was there, its sha256, rather than left
alone or deleted (the full list, and why each field is or is not covered,
is docs/retention.md §5). The chain still verifies afterward, and what
changed is recorded in it too, as the new last event, session.erasure —
an erasure that could not itself be audited would undercut the reason this
record exists at all. That event also anchors the exact chain head this
rewrite replaced, so a reader who already holds an earlier export of this
session can confirm the erased chain is its honest successor rather than a
fabrication.

This is destructive and cannot be undone from this record: the content is
gone, not kept anywhere by KelyfOS. That does not reach a copy this record
was never involved in — a report already exported before the erasure ran
carries the original chain, signed or not, and this command has no way to
know one exists.

Flags may go on either side of the id, the same as `+"`kelyfos verify`"+`.

`)
		fs.PrintDefaults()
	}
	ids, err := parseAround(fs, argv)
	if err != nil {
		return err
	}
	if len(ids) != 1 {
		fs.Usage()
		return &exitError{code: 2}
	}
	if *reason == "" {
		return errors.New("-reason is required: an erasure is worth saying why, in the record itself")
	}
	id := ids[0]

	live, err := livePausedSessions()
	if err != nil {
		return err
	}
	if live[id] {
		return fmt.Errorf("%s is a currently paused session's own chain — resume it or discard it "+
			"(kelyfos sessions rm) before erasing its record", id)
	}
	if hasLiveRunDir(id) {
		return fmt.Errorf("%s has a live run directory and may still be running — erasing a chain "+
			"still being written to would race the writer", id)
	}
	// hasLiveRunDir alone only sees a sandbox whose OWN id names its run
	// directory. A team's chain and a `kelyfos serve-mcp` process's own
	// audit chain are both opened under an id sandbox.NewID() mints that is
	// never any sandbox's own id, so no run directory is ever named for
	// either — invisible to the check above even while very much alive
	// (B1). RunningSessions asks the other direction: is any live
	// sandbox's own RecordSession() this id, whichever sandbox actually
	// holds a run directory. It still cannot see a live serve-mcp
	// process's own audit session, which names no sandbox's Session field
	// at all — recorder.Erase's own refusal of a chain with no
	// session.end anywhere in it is what catches that case, underneath
	// this one.
	running, err := sandbox.RunningSessions()
	if err != nil {
		return err
	}
	if running[id] {
		return fmt.Errorf("%s has a live sandbox writing into it right now (a team member, or a "+
			"machine kelyfos serve-mcp created) — erasing a chain still being written to would "+
			"race the writer", id)
	}

	redacted, err := recorder.Erase(sandbox.Root(), id, *reason)
	if err != nil {
		return err
	}

	// Re-read and re-verify rather than trusting Erase's own return value —
	// the same "check what you just wrote" rule every other destructive
	// door in this product follows, applied to a rewrite instead of an
	// append.
	blob, err := os.ReadFile(recorder.Path(sandbox.Root(), id))
	if err != nil {
		return err
	}
	n, head, verr := recorder.Verify(bytes.NewReader(blob))
	if verr != nil {
		return fmt.Errorf("erased %s but the rewritten chain does not verify: %w", id, verr)
	}
	fmt.Printf("erased %s: %d event(s) redacted, %d events, chain intact\n", id, redacted, n)
	fmt.Printf("  chain head  %s\n", head)
	return nil
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

	// Opened before Restore, and kept open for the resumed machine's whole
	// life rather than closed the instant the resume event is written, as this
	// used to do: an OOM kill or a plugin crash any time after this point
	// otherwise left no trace in the session it resumed into (F3).
	rec, recErr := recorder.Open(sandbox.Root(), meta.Session)
	if recErr == nil {
		opts.OnGuestEvent = guestEventRecorder(rec, "", snapMeta.MemMiB)
		defer rec.Close()
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
		// The receipt is sampled before Shutdown, the same as every other
		// teardown in this product (E1-7). No blocked_packets here: a session
		// with a network refuses to resume through this door (above), so
		// there is never one to sample.
		if rec != nil {
			if u, err := sb.State.Sample(); err == nil {
				_ = rec.Append(recorder.Event{
					Type:       recorder.TypeResourceSummary,
					CPUSeconds: u.CPUSeconds, PeakRSSKiB: u.PeakRSSKiB,
					NetInBytes: u.NetInBytes, NetOutBytes: u.NetOutBytes,
					DiskReadBytes: u.DiskReadBytes, DiskWriteBytes: u.DiskWriteBytes,
					MemMiB: sb.State.MemMiB, VcpuCount: sb.State.VcpuCount, CPUQuota: sb.State.CPUQuota,
				})
			}
		}
		if err := sb.Shutdown(10 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos: shutdown: %v\n", err)
		}
	}()

	if rec != nil {
		_ = rec.Append(recorder.Event{Type: recorder.TypeSessionResume, Name: name,
			BootMS: elapsed.Milliseconds(), Reason: strings.Join(differences, ", ")})
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
	// The image has to still be there, and this is not a formality (P6-27).
	//
	// When it was not, SyncBack did not fail — it extracted nothing, renamed the
	// person's project directory away and put an empty one in its place, and
	// this function printed "workspace written back". A sync-back that cannot
	// read its source must change nothing at all: the directory on disk is worth
	// more than the sync, and refusing is the only outcome that keeps it.
	if info, err := os.Stat(image); err != nil || info.Size() == 0 {
		fmt.Fprintf(os.Stderr,
			"kelyfos: the workspace image for this session is not readable (%s), so the host\n"+
				"    directory was left exactly as it is rather than replaced with an empty one.\n"+
				"    Nothing was written back and nothing was removed.\n", image)
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
