package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// kelyfos runs, and kelyfos rerun (E5-6).
//
// There is no run database. Every fact these two commands need is already in
// the flight recorder — what booted, from where, with which command, for how
// long, and what it exited with — so the history is an *index* built by reading
// what is there, and never a second record that could disagree with the first.
//
// That is the whole design decision. A separate history file would be a thing
// to keep in step, to migrate, and eventually to find out of date; the session
// logs are already written, already hash-chained, and already the thing anyone
// would check.

// runRow is one line of history.
type runRow struct {
	Session  string
	When     time.Time
	Image    string
	Arch     string
	Command  string
	Argv     []string
	Cwd      string
	Kind     string // run, team, serve-mcp, restore…
	Exit     *int
	Reason   string
	Duration time.Duration
	Events   int
}

func runsCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos runs", flag.ExitOnError)
	var (
		limit = fs.Int("n", 20, "how many to show, newest first (0 = all)")
		all   = fs.Bool("all", false, "show every recorded session")
		full  = fs.Bool("full", false, "print the whole command rather than one line of it")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos runs [flags]

What has run on this machine, newest first, read from the session records
themselves rather than from a separate history — so it cannot disagree with
`+"`kelyfos log`"+`, and there is nothing to keep in step.

    kelyfos runs
    kelyfos rerun 7f3c1a2b

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	rows, err := readRuns()
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Println("nothing has run on this machine yet.")
		return nil
	}
	if !*all && *limit > 0 && len(rows) > *limit {
		rows = rows[:*limit]
	}

	// Widths from the data, so a column is as wide as it has to be and no
	// wider. A fixed-width table wastes half a terminal on short image names.
	w := struct{ image, exit, dur int }{5, 4, 8}
	for _, r := range rows {
		w.image = max(w.image, len(r.Image))
		w.exit = max(w.exit, len(exitCell(r)))
		w.dur = max(w.dur, len(durationCell(r.Duration)))
	}
	fmt.Printf("%-8s  %-16s  %-*s  %-*s  %-*s  %s\n",
		"ID", "WHEN", w.image, "IMAGE", w.exit, "EXIT", w.dur, "TOOK", "COMMAND")
	for _, r := range rows {
		cmd := r.Command
		if !*full {
			cmd = oneLine(cmd, 60)
		}
		fmt.Printf("%-8s  %-16s  %-*s  %-*s  %-*s  %s\n",
			r.Session, r.When.Format("2006-01-02 15:04"),
			w.image, or(r.Image, "—"), w.exit, exitCell(r),
			w.dur, durationCell(r.Duration), cmd)
	}
	return nil
}

// exitCell is what a run ended as. An open session has no answer yet and says
// so rather than showing a zero, because "still running" and "succeeded" are
// the two things a reader most needs to be able to tell apart.
func exitCell(r runRow) string {
	switch {
	case r.Exit != nil:
		return strconv.Itoa(*r.Exit)
	case r.Reason == "":
		return "open"
	case r.Reason == "shutdown" || r.Reason == "command_exited":
		return "—"
	default:
		return r.Reason
	}
}

func durationCell(d time.Duration) string {
	switch {
	case d == 0:
		return "—"
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return d.Round(time.Second).String()
	}
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func or(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// readRuns builds the index. One pass per session file, and that pass parses
// every event in the file: a listing costs what this machine has recorded, not
// what it is about to print — `-n 20` trims the rows once they have all been
// built.
//
// That is not an oversight and there is no early stop to be had, which is worth
// saying plainly because this comment once claimed the opposite. A row's exit
// status, reason and duration come from session.end — by construction the last
// event a session ever writes — and its event count and its team size are facts
// about the whole file, so no prefix of a record is enough to fill a row in.
//
// Memory is the one part that could be smaller: recorder.Read materialises a
// session's events rather than handing them over one at a time, so the peak is
// the longest single session. That is bounded per file and never the whole
// directory, and shaving it would mean a second copy of the recorder's parsing
// rules living up here to drift out of step with the first — a worse trade than
// the allocation.
func readRuns() ([]runRow, error) {
	dir := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	var rows []runRow
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		row, ok, err := readRun(filepath.Join(dir, e.Name(), "events.jsonl"), e.Name())
		if err != nil {
			// Genuinely missing (ENOENT) never reaches here — readRun turns
			// that into ok=false, nil below, because a session directory can
			// legitimately race with its own creation. Anything else —
			// permission denied, an I/O error — is a session that exists but
			// couldn't be read, and the "one row per session directory"
			// guarantee (docs/events.md §6) means that has to be visible
			// rather than indistinguishable from a session that was never
			// there.
			fmt.Fprintf(os.Stderr, "kelyfos: could not read session %s: %v\n", e.Name(), err)
			continue
		}
		if !ok {
			continue
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].When.After(rows[j].When) })
	return rows, nil
}

func readRun(path, session string) (runRow, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return runRow{}, false, nil
		}
		return runRow{}, false, err
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil || len(events) == 0 {
		return runRow{}, false, nil
	}
	row := runRow{Session: session, Events: len(events)}
	agents := map[string]bool{}
	first := ""
	for _, ev := range events {
		switch ev.Type {
		case recorder.TypeSessionStart:
			if row.When.IsZero() {
				row.When = parseTS(ev.TS)
				row.Image, row.Arch, row.Argv, row.Cwd = ev.Image, ev.Arch, ev.Argv, ev.Cwd
				row.Command = describeArgv(ev.Argv)
				row.Kind = kindOf(ev)
			}
		case recorder.TypeSessionEnd:
			row.Reason = ev.Reason
			row.Duration = time.Duration(ev.DurationMS) * time.Millisecond
			row.Exit = ev.Code
		}
		if ev.Agent != "" {
			agents[ev.Agent] = true
		}
		// A chain that starts with a command and never with a session is a
		// machine somebody attached to, whose own launch is recorded elsewhere.
		// Showing it with an empty command would be the listing hiding a real
		// thing; showing the first command it ran says what it is.
		if first == "" && ev.Type == recorder.TypeCommandStart && len(ev.Cmd) > 0 {
			first = strings.Join(ev.Cmd, " ")
		}
	}
	if row.Command == "" && first != "" {
		row.Command = "(attached) " + first
	}
	if row.Kind == "team" {
		row.Command = fmt.Sprintf("team of %d — %s", len(agents), row.Command)
	}
	if row.When.IsZero() {
		row.When = parseTS(events[0].TS)
	}
	return row, true, nil
}

// parseTS reads the recorder's own timestamp format. An unparseable one is the
// zero time rather than an error: a listing should still show a session whose
// first line is damaged, with the damage visible.
func parseTS(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", s)
	if err != nil {
		return time.Time{}
	}
	return t.Local()
}

func kindOf(ev recorder.Event) string {
	if ev.Reason == recorder.ReasonServeMCP {
		return "serve-mcp"
	}
	if len(ev.Argv) > 1 {
		return ev.Argv[1]
	}
	return "run"
}

// describeArgv is the command as it was typed, minus the binary's own path —
// which is noise, and which differs between an installed kelyfos and one run
// out of a build directory.
func describeArgv(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	return "kelyfos " + strings.Join(argv[1:], " ")
}

func rerunCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos rerun", flag.ExitOnError)
	dry := fs.Bool("print", false, "print what would run, and do not run it")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos rerun <session-id> [flags]

Runs a recorded session again: the same command, from the same directory,
under the policy file that was in force at the time. It prints a provenance
line first saying exactly what it is reproducing and from when, because a
command that reruns something invisible is a command nobody should trust.

The policy is the *frozen* copy taken when that run started, not whatever
kelyfos.toml says now. A rerun that quietly picked up a policy edited since is
not a rerun.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("rerun needs exactly one session id; `kelyfos runs` lists them")
	}
	want := fs.Arg(0)

	rows, err := readRuns()
	if err != nil {
		return err
	}
	row, err := findRun(rows, want)
	if err != nil {
		return err
	}
	if len(row.Argv) < 2 {
		return fmt.Errorf("session %s does not record how it was launched, so there is "+
			"nothing to repeat.\n    it was recorded by a kelyfos older than this one",
			row.Session)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	next := append([]string{row.Argv[0]}, row.Argv[1:]...)
	frozen := frozenPolicyPath(row.Session)
	if frozen != "" && !hasFlag(next, "policy") {
		// Inserted straight after the subcommand, where a flag belongs.
		next = append(next[:2:2], append([]string{"--policy", frozen}, next[2:]...)...)
	}

	fmt.Fprintf(os.Stderr, "kelyfos: rerunning session %s from %s\n",
		row.Session, row.When.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(os.Stderr, "    command   %s\n", describeArgv(next))
	if row.Cwd != "" {
		fmt.Fprintf(os.Stderr, "    directory %s\n", row.Cwd)
	}
	switch {
	case frozen != "":
		fmt.Fprintf(os.Stderr, "    policy    %s (frozen when that run started)\n", frozen)
	default:
		fmt.Fprintf(os.Stderr, "    policy    none was frozen; whatever kelyfos.toml is found now applies\n")
	}
	if *dry {
		return nil
	}

	if row.Cwd != "" {
		if err := os.Chdir(row.Cwd); err != nil {
			return fmt.Errorf("the directory that run was launched from is gone: %w\n"+
				"    run it yourself from wherever the project lives now:\n      %s",
				err, describeArgv(next))
		}
	}
	// Replaced rather than spawned, so the rerun *is* this process: one exit
	// status, one signal target, and nothing in between to get the two out of
	// step.
	return syscall.Exec(self, next, os.Environ())
}

// findRun accepts a prefix, because a session id is eight hex characters and
// nobody should have to type all of them from a listing.
func findRun(rows []runRow, want string) (runRow, error) {
	var hits []runRow
	for _, r := range rows {
		if r.Session == want {
			return r, nil
		}
		if strings.HasPrefix(r.Session, want) {
			hits = append(hits, r)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return runRow{}, fmt.Errorf("no recorded session starts with %q\n"+
			"    `kelyfos runs` lists what there is", want)
	default:
		ids := make([]string, len(hits))
		for i, h := range hits {
			ids[i] = h.Session
		}
		return runRow{}, fmt.Errorf("%q matches %s; say more of it",
			want, strings.Join(ids, ", "))
	}
}

func hasFlag(argv []string, name string) bool {
	for _, a := range argv {
		if a == "-"+name || a == "--"+name ||
			strings.HasPrefix(a, "-"+name+"=") || strings.HasPrefix(a, "--"+name+"=") {
			return true
		}
	}
	return false
}

// frozenPolicyPath is the copy of kelyfos.toml taken when a session started, or
// "" when there was none to take. It sits beside that session's record, which
// is deliberately outside the run directory: the record outlives the machine,
// and so must the policy it ran under.
func frozenPolicyPath(session string) string {
	path := filepath.Join(recorder.SessionsDir(sandbox.Root()), session, "kelyfos.toml")
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

// freezeRunPolicy stores the policy this run is about to use beside its record.
//
// A few kilobytes per session, and it is what makes `rerun` mean anything: the
// alternative is re-reading whatever kelyfos.toml says at rerun time, which
// reproduces the command and not the run.
func freezeRunPolicy(session string, cfg *config.Config) {
	if cfg == nil || cfg.Path == "" {
		return
	}
	blob, err := os.ReadFile(cfg.Path)
	if err != nil {
		return
	}
	dest := filepath.Join(recorder.SessionsDir(sandbox.Root()), session, "kelyfos.toml")
	// Best effort on purpose: a run must not fail because its history could not
	// be made more useful.
	_ = os.WriteFile(dest, blob, 0o600)
}
