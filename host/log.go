package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/ikapa-dev/kelyfos/internal/digest"
	"github.com/ikapa-dev/kelyfos/internal/otlp"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/report"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func logCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos log", flag.ExitOnError)
	var (
		id           = fs.String("session", "", "session id (default: the most recent)")
		follow       = fs.Bool("follow", false, "stream events as they are recorded")
		followShort  = fs.Bool("f", false, "alias for --follow")
		verify       = fs.Bool("verify", false, "check the hash chain and report the first break")
		asJSON       = fs.Bool("json", false, "print the raw events instead of a readable replay")
		list         = fs.Bool("list", false, "list recorded sessions")
		export       = fs.String("export", "", "write a self-contained HTML report to this path")
		exportOTLP   = fs.String("export-otlp", "", "write an OTLP-JSON trace export to this path (one-way, never read back — docs/otlp.md)")
		signKey      = fs.String("sign-key", "", "sign the exported report with this ed25519 private key (PEM PKCS#8)")
		refresh      = fs.Bool("refresh", false, "keep rewriting --export as the session continues, atomically, with a meta-refresh tag — no server, no socket; Ctrl-C to stop")
		refreshEvery = fs.Duration("refresh-every", 2*time.Second, "how often --refresh rewrites the export (only meaningful with --refresh)")
	)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos log [flags]

Replays a session's flight recorder — every command, its output, and from
phase 2 every egress attempt and secret use. The schema is documented in
docs/events.md.

--export works against a session that is still running, not only a finished
one. --refresh turns that into the honest answer to "live" for anyone who
does not want a listener: it rewrites the same file atomically on a timer and
the page it writes carries a <meta http-equiv="refresh">, so a browser tab
already open on it keeps reloading and shows whatever the last rewrite wrote
— no server, no socket, anywhere in that path. It stops on its own once the
session ends (that last write drops the refresh tag too, since nothing more
is coming) or on Ctrl-C.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *followShort {
		*follow = true
	}

	if *list {
		return listSessions()
	}

	sessionID, err := resolveSession(*id)
	if err != nil {
		return err
	}
	path := recorder.Path(sandbox.Root(), sessionID)

	if *export != "" {
		if *refresh {
			// ctx/stop live here, at the command's own entry point, the same
			// place every other long-running kelyfos command wires up
			// Ctrl-C (team up, run, serve-mcp, fork, snapshot restore) —
			// rather than inside the loop below, which takes the context as
			// a plain argument and is exercised without a real OS signal in
			// host/log_test.go.
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return refreshExportSession(ctx, sessionID, path, *export, *signKey, *refreshEvery)
		}
		return exportSession(sessionID, path, *export, *signKey)
	}
	if *exportOTLP != "" {
		return exportOTLPSession(sessionID, path, *exportOTLP)
	}
	if *refresh {
		return errors.New("--refresh rewrites an export; give --export a path as well")
	}
	if *signKey != "" {
		return errors.New("--sign-key signs an export; give --export a path as well")
	}
	if *verify {
		return verifySession(sessionID, path)
	}
	if *follow {
		return followSession(path, *asJSON)
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", sessionID, err)
	}
	defer f.Close()
	return replay(f, *asJSON)
}

func resolveSession(id string) (string, error) {
	if id != "" {
		// A team member's sandbox id has no record of its own: everything it
		// did was written into the team's chain (E2-7). Following the redirect
		// is friendlier than a "no flight recorder" for a machine that plainly
		// existed — and it says so, rather than quietly showing something else.
		if st, err := sandbox.Load(id); err == nil && st.Session != "" && st.Session != id {
			fmt.Fprintf(os.Stderr, "kelyfos: %s is agent %q in team session %s; showing the team's record\n",
				id, st.Agent, st.Session)
			return st.Session, nil
		}
		return id, nil
	}
	dir := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return "", fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	type cand struct {
		name string
		mod  time.Time
	}
	var found []cand
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := os.Stat(filepath.Join(dir, e.Name(), "events.jsonl"))
		if err != nil {
			continue
		}
		found = append(found, cand{e.Name(), info.ModTime()})
	}
	if len(found) == 0 {
		return "", fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].mod.After(found[j].mod) })
	return found[0].name, nil
}

func listSessions() error {
	dir := recorder.SessionsDir(sandbox.Root())
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("no sessions recorded yet (looked in %s)", dir)
	}
	// ReadDir returns them by filename, which for sessions is a random hex id —
	// so the listing came out in an order with no meaning, and `head -1` gave an
	// arbitrary session rather than the obvious one. Newest first, matching what
	// every subcommand means by "the most recent" (F-D33).
	type row struct {
		name string
		mod  time.Time
		line string
	}
	var rows []row
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "events.jsonl")
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		events, _ := recorder.Read(f)
		f.Close()
		state := "open"
		served := false
		agents := map[string]bool{}
		for _, ev := range events {
			if ev.Type == recorder.TypeSessionEnd {
				state = ev.Reason
			}
			if ev.Type == recorder.TypeSessionStart && ev.Reason == recorder.ReasonServeMCP {
				served = true
			}
			if ev.Agent != "" {
				agents[ev.Agent] = true
			}
		}
		// A session covering several machines is worth marking: it is one chain
		// for all of them, and a reader looking for "the worker's log" needs to
		// know there is not one. Which noun depends on what kind of session it
		// is — a team's machines are agents, a server's are sandboxes — and
		// calling a serve-mcp session "a team of 1" would be a plain untruth.
		what := ""
		switch {
		case served:
			what = fmt.Sprintf("  serve-mcp, %d sandbox(es)", len(agents))
		case len(agents) > 0:
			what = fmt.Sprintf("  team of %d", len(agents))
		}
		rows = append(rows, row{name: e.Name(), mod: info.ModTime(),
			line: fmt.Sprintf("%s  %s  %4d events  %s%s",
				e.Name(), info.ModTime().Format("2006-01-02 15:04:05"), len(events), state, what)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].mod.After(rows[j].mod) })
	for _, r := range rows {
		fmt.Println(r.line)
	}
	return nil
}

// exportSession renders the report from the record's bytes.
//
// The bytes rather than the parsed events, because the report carries the
// record inside it now: the page a reader sees and the record they can check
// are made from one blob by one call, so an export whose timeline and evidence
// disagree cannot be produced (P6-6).
func exportSession(id, path, dest, signKey string) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", id, err)
	}
	var key ed25519.PrivateKey
	if signKey != "" {
		if key, err = report.LoadSigningKey(signKey); err != nil {
			return err
		}
	}

	n, err := atomicWriteReport(dest, id, blob, key, 0)
	if err != nil {
		return err
	}

	_, head, verifyErr := recorder.Verify(bytes.NewReader(blob))
	info, _ := os.Stat(dest)
	fmt.Printf("wrote %s (%d events, %d bytes)\n", dest, n, sizeOf(info))
	if verifyErr != nil {
		fmt.Printf("  the chain does NOT verify: %v\n", verifyErr)
		fmt.Printf("  the report says so, and still carries the record so a reader can see for themselves\n")
		return nil
	}
	if n == 0 {
		// No head, and nothing to check. Printing "chain head" with nothing
		// after it and then advertising a command that refuses the file is two
		// wrong answers in three lines.
		fmt.Printf("  the record is empty, so there is no chain head and nothing to verify\n")
		return nil
	}
	// The head is printed here so whoever sends the file can quote it out of
	// band. A reader who was told the head separately is checking the record
	// against something the sender could not change afterwards, which is the
	// most an unsigned export can offer — and P6-7 is what removes the "out of
	// band" from that sentence.
	fmt.Printf("  chain head %s\n", head)
	if key != nil {
		pub := report.PublicKeyHex(key.Public())
		fmt.Printf("  signed by %s\n", pub)
		fmt.Printf("  a reader learns nothing from that unless they already have it; send it to them" +
			" some other way than in this file\n")
	}
	fmt.Printf("  anyone can check it: kelyfos verify %s\n", dest)
	return nil
}

// exportOTLPSession renders this session's chain as an OTLP-JSON trace
// export — a one-way, lossy projection for interoperability with existing
// observability tooling (internal/otlp, docs/otlp.md). D59: versioned apart
// from the flight recorder and never an input to `kelyfos verify`; nothing
// here touches internal/recorder's Event struct or its frozen field order.
//
// Unlike exportSession, this reads the record's parsed events rather than
// carrying its raw bytes: the OTLP file is a projection meant for an
// observability backend, not a document a recipient re-verifies against the
// chain the way an HTML report is (recipe 6, docs/cookbook.md) — so there is
// no record blob to embed, and nothing here to sign.
func exportOTLPSession(id, path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", id, err)
	}
	events, err := recorder.Read(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("reading flight recorder for session %s: %w", id, err)
	}

	trace, err := otlp.Build(id, events)
	if err != nil {
		return err
	}
	blob, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')

	// Same atomic-write discipline as exportSession above: rendered beside
	// the destination and moved into place, never written straight over it.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".kelyfos-export-*")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if _, err := tmp.Write(blob); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), createMode()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return err
	}

	spans := 0
	for _, rs := range trace.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			spans += len(ss.Spans)
		}
	}
	fmt.Printf("wrote %s (%d spans)\n", dest, spans)
	fmt.Printf("  one-way and lossy: not read back by kelyfos, and never an input to kelyfos verify\n")
	return nil
}

// atomicWriteReport renders chain into dest via a temp file in dest's own
// directory, renamed into place — never written straight over the
// destination. It is exportSession's own atomic-write step (P6-18), factored
// out so the --refresh loop below writes a report exactly one way rather
// than growing a second copy of "how a report gets safely onto disk": an
// export that fails partway must leave what was already there alone, whether
// this is the only write that will ever happen or the two-hundredth in a
// refresh loop.
func atomicWriteReport(dest, id string, chain []byte, key ed25519.PrivateKey, refreshSeconds int) (n int, err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".kelyfos-export-*")
	if err != nil {
		return 0, err
	}
	defer func() {
		tmp.Close()
		_ = os.Remove(tmp.Name()) // a no-op once the rename has happened
	}()
	n, err = report.RenderRefreshable(tmp, id, chain, key, refreshSeconds)
	if err != nil {
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	// os.CreateTemp makes a 0600 file and a rename carries that mode with it, so
	// without this every exported report is owner-only — which is not what
	// os.Create did before the export became atomic, and not what a document
	// written to be handed to somebody should be (P6-18, umask.go).
	if err := os.Chmod(tmp.Name(), createMode()); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return 0, err
	}
	return n, nil
}

// refreshExportSession is P7-9: --export against a session that has not
// ended, kept current. It rewrites dest every interval, atomically
// (atomicWriteReport), from whatever the flight recorder holds at that
// moment — the same one-blob-one-call render exportSession uses, just run
// on a clock. The page it writes carries a <meta http-equiv="refresh">, so a
// browser tab already open on dest reloads itself and picks up each rewrite
// with nothing more asked of the person watching it.
//
// There is no socket anywhere in this: the loop below opens exactly the
// files exportSession already opens (the session's own events.jsonl, read;
// dest, written), on a timer, in this one process. "Live" here means a file
// changing on disk and a browser polling it, which is the whole point — it
// is the honest answer for anyone who does not want a listener, and it works
// whether or not P7-12's viewer ever runs.
// minRefreshInterval is the floor on --refresh-every. Below it the loop stops
// being a "how often does the export change" knob and becomes a syscall
// storm: an unbounded --refresh-every 1ns measured at over a full CPU-second
// of work per wall-second, against a meta tag whose own content is whole
// seconds — no browser could ever observe anything below this floor either.
const minRefreshInterval = 100 * time.Millisecond

func refreshExportSession(ctx context.Context, id, path, dest, signKey string, interval time.Duration) error {
	if interval < minRefreshInterval {
		return fmt.Errorf("--refresh-every must be at least %s, got %s", minRefreshInterval, interval)
	}
	var key ed25519.PrivateKey
	if signKey != "" {
		var err error
		if key, err = report.LoadSigningKey(signKey); err != nil {
			return err
		}
	}
	// The meta tag's content is whole seconds; a sub-second interval still
	// rewrites the file that often, it just asks the browser to reload no
	// more than once a second rather than claiming a granularity HTML's own
	// refresh mechanism does not have.
	refreshSecs := int((interval + time.Second/2) / time.Second)
	if refreshSecs < 1 {
		refreshSecs = 1
	}

	fmt.Printf("refreshing %s from session %s every %s\n", dest, id, interval)
	fmt.Println("  atomic rewrite + <meta refresh> — no server, no socket. Ctrl-C to stop.")

	var last []byte
	var lastLog string
	wrote := false
	log := func(line string) {
		// A vanished record or a permanently-invalid export repeats the same
		// diagnostic every tick — at the floor above that is up to ten lines a
		// second. One line per new problem, not one per poll.
		if line == lastLog {
			return
		}
		lastLog = line
		fmt.Println(line)
	}
	for {
		blob, err := os.ReadFile(path)
		switch {
		case err != nil:
			// The session may not have written a single line yet — a refresh
			// started in the same breath as `team up` races its own first
			// event. Transient either way: say so and keep polling rather
			// than exiting a loop the caller asked to run "until it's done."
			log(fmt.Sprintf("  %s waiting for the flight recorder: %v", refreshStamp(), err))
		case wrote && bytes.Equal(blob, last):
			// Nothing new since the last rewrite. The meta tag already has an
			// open tab polling dest on its own schedule, so there is nothing
			// this tick needs to redo — an unconditional rewrite here would
			// mean an atomic rename every interval for a team that is simply
			// idle between messages.
			//
			// wrote guards this: bytes.Equal(nil, nil) is true, so without it
			// a session file that exists but is still empty (created by
			// recorder.Open, nothing Appended yet) would match a nil `last`
			// on the very first tick and the loop would sit there forever,
			// silently, never writing dest and never saying why.
		default:
			ended, n, werr := writeRefreshedReport(dest, id, blob, key, refreshSecs)
			if werr != nil {
				var wfe *refreshWriteError
				if errors.As(werr, &wfe) {
					// Unlike a parse race, a write failure — a destination
					// directory that does not exist, a read-only filesystem,
					// no space left — will not resolve itself on the next
					// tick. The one-shot --export exits 1 on the identical
					// error; --refresh does the same rather than retrying it
					// forever under "export not yet valid," which is
					// actively wrong for a write-side fault.
					return fmt.Errorf("writing %s: %w", dest, wfe.err)
				}
				// A read racing an in-flight Append could in principle catch
				// a torn final line; Append writes each event with one
				// O_APPEND syscall, so the kernel does not hand a concurrent
				// reader a half-written line in practice, but treating a
				// parse failure as fatal here would turn a one-tick race
				// into the whole command exiting. Try again next tick.
				log(fmt.Sprintf("  %s export not yet valid, retrying: %v", refreshStamp(), werr))
			} else {
				last = blob
				wrote = true
				log(fmt.Sprintf("  %s wrote %s (%d events, %d chain bytes)", refreshStamp(), dest, n, len(blob)))
				if ended {
					fmt.Println("session ended — that was the final export, with no further meta-refresh; stopping")
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			if wrote {
				// A tab left open on dest still carries the refresh tag from
				// its last rewrite and will keep re-fetching a file nothing
				// will ever change again unless this last write drops it —
				// the same reason session.end drops it, applied to the other
				// way the loop can stop.
				if _, werr := atomicWriteReport(dest, id, last, key, 0); werr == nil {
					fmt.Println("\nstopped — wrote a final export with no further meta-refresh")
				} else {
					fmt.Printf("\nstopped (final export failed: %v)\n", werr)
				}
			} else {
				fmt.Println("\nstopped")
			}
			return nil
		case <-time.After(interval):
		}
	}
}

// refreshWriteError marks an error as coming from atomicWriteReport rather
// than from parsing blob, so refreshExportSession's loop can tell a
// transient read/parse race (retry next tick) apart from a write-side fault
// like a missing destination directory or a full disk (not going away on its
// own — surface it and stop, the way the one-shot --export already does).
type refreshWriteError struct{ err error }

func (e *refreshWriteError) Error() string { return e.err.Error() }
func (e *refreshWriteError) Unwrap() error { return e.err }

// writeRefreshedReport folds blob to learn whether the session it came from
// has already ended, then writes it — dropping the refresh tag on that last
// write, because a page nothing will update again should not ask a reader's
// browser to keep asking.
func writeRefreshedReport(dest, id string, blob []byte, key ed25519.PrivateKey, refreshSecs int) (ended bool, n int, err error) {
	parsed, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		return false, 0, err
	}
	d := digest.Walk(parsed)
	ended = d.Ended != ""
	secs := refreshSecs
	if ended {
		secs = 0
	}
	n, err = atomicWriteReport(dest, id, blob, key, secs)
	if err != nil {
		return false, 0, &refreshWriteError{err}
	}
	return ended, n, nil
}

// refreshStamp is the wall-clock prefix on the refresh loop's own progress
// lines — one file changing over minutes needs a clock beside each line
// exportSession's single-shot output never did.
func refreshStamp() string { return time.Now().Format("15:04:05") }

func verifySession(id, path string) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", id, err)
	}
	n, head, err := verifiedChain(blob)
	if err != nil {
		fmt.Printf("session %s: FAILED after %d events\n  %v\n", id, n, err)
		return &exitError{code: 1}
	}
	// Deferred because the verdict has two shapes below — a team's names its
	// members, a single sandbox's does not — and the head belongs under both.
	// A reader on this machine quotes it to whoever they send the export to,
	// which is the comparison an unsigned report rests on.
	defer func() { fmt.Printf("  chain head %s\n", head) }()
	// For a team, "the chain" is the whole team's — one file covering every
	// agent's commands, messages, store accesses and egress. Saying which
	// agents it covers is what makes the claim checkable: a reader can compare
	// it against the team they declared and see nothing is missing (E2-7).
	agents, err := sessionAgents(path)
	if err == nil && len(agents) > 0 {
		noun := "agents"
		if served, _ := sessionIsServed(path); served {
			noun = "sandboxes"
		}
		fmt.Printf("session %s: chain intact, %d events verified across %d %s (%s)\n",
			id, n, len(agents), noun, strings.Join(agents, ", "))
		return nil
	}
	fmt.Printf("session %s: chain intact, %d events verified\n", id, n)
	return nil
}

// sessionAgents is every agent name that appears in a session, in the order
// they were first seen — which is boot order, and so reads like the team.
func sessionAgents(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range events {
		if e.Agent != "" && !seen[e.Agent] {
			seen[e.Agent] = true
			out = append(out, e.Agent)
		}
	}
	return out, nil
}

func followSession(path string, asJSON bool) error {
	// Wait for the file: `kelyfos log --follow` is a natural thing to start
	// before, or at the same time as, the sandbox it is watching.
	var f *os.File
	for i := 0; ; i++ {
		var err error
		if f, err = os.Open(path); err == nil {
			break
		}
		if i > 100 {
			return fmt.Errorf("no flight recorder appeared at %s", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			printEvent(line, asJSON)
		}
		if err == io.EOF {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
	}
}

// replayRecord prints a record a reader was handed, rather than one of this
// machine's sessions. Same renderer as `kelyfos log`, deliberately: a reader
// comparing an export against its own record must be looking at the same words
// in both places, or the comparison proves nothing.
func replayRecord(chain []byte, asJSON bool) error {
	return replay(bytes.NewReader(chain), asJSON)
}

func replay(r io.Reader, asJSON bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), recorder.MaxLine)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		printEvent(append([]byte(nil), sc.Bytes()...), asJSON)
	}
	return sc.Err()
}

func printEvent(line []byte, asJSON bool) {
	if asJSON {
		os.Stdout.Write(line)
		if len(line) == 0 || line[len(line)-1] != '\n' {
			os.Stdout.Write([]byte{'\n'})
		}
		return
	}
	var e recorder.Event
	if err := json.Unmarshal(line, &e); err != nil {
		// A malformed line reaches here with none of the frozen schema's own
		// guarantees — kelyfos log's default path never checks the hash
		// chain before replaying it, so a corrupted or tampered line is not
		// ruled out. proto.SafeText on the raw bytes closes the same gap
		// the rest of this function does: an unparseable line is exactly
		// where a guest-controlled or hand-edited byte sequence is least
		// constrained.
		fmt.Printf("  ?? unparseable event: %s\n", proto.SafeText(strings.TrimSpace(string(line))))
		return
	}
	// Once, here, rather than at each of the fifty-odd fields the switch below
	// reads (P7-17/F20, second review round). The per-field version missed
	// nineteen of them, e.Agent included — which is the `[who]` prefix on
	// nearly every line.
	e = safeEvent(e)

	ts := e.TS
	if len(ts) > 23 {
		ts = ts[11:23]
	}
	// In a team the same chain carries several machines, so the lines that are
	// about one of them say which. Outside a team `who` is empty and every line
	// below reads exactly as it did before (E2-7).
	who := ""
	if e.Agent != "" {
		who = "[" + e.Agent + "] "
	}
	switch e.Type {
	case recorder.TypeSessionStart:
		// The reason is how a restored or forked machine says what it is. A
		// cold boot writes none, so this stays quiet for the common case and
		// tells the whole story for the one where it matters.
		why := ""
		if e.Reason != "" {
			why = " " + proto.SafeText(e.Reason)
		}
		// A session with no single image — a team's, a server's — says nothing
		// rather than "image=" followed by a hole.
		image := ""
		if e.Image != "" {
			image = "image=" + e.Image + " "
		}
		fmt.Printf("%s  session start   %sarch=%s kelyfos=%s%s\n", ts, image, e.Arch, e.Kelyfos, why)
	case recorder.TypeMCPHostCall:
		fmt.Printf("%s  %sclient call    %s\n", ts, who, proto.SafeText(strings.TrimSpace(e.Name+" "+e.Args)))
	case recorder.TypeMCPHostResult:
		outcome := e.Outcome
		if e.Error != nil {
			outcome = "refused: " + e.Error.Message
		}
		fmt.Printf("%s  %sclient result  %s %s (%d ms)\n", ts, who, proto.SafeText(e.Name), proto.SafeText(outcome), e.DurationMS)
	case recorder.TypePluginCall:
		outcome := e.Outcome
		what := e.Name + "_" + e.Tool
		if e.Args != "" {
			what += " " + e.Args
		}
		fmt.Printf("%s  %splugin call    %s  %s (%d ms)\n", ts, who, proto.SafeText(what),
			proto.SafeText(strings.TrimSpace(outcome)), e.DurationMS)
	case recorder.TypePluginCrash:
		fmt.Printf("%s  %splugin stopped %s  %s\n", ts, who, proto.SafeText(e.Name), proto.SafeText(e.Reason))
	case recorder.TypeShellStart:
		where := ""
		if e.Path != "" {
			where = " · recording to " + proto.SafeText(e.Path)
		}
		fmt.Printf("%s  %sshell opened   %s\n", ts, who, strings.TrimSpace(where))
	case recorder.TypeShellEnd:
		code := 0
		if e.Code != nil {
			code = *e.Code
		}
		// Two endings write this event and only the reason tells them apart. A
		// shell that exited says so through its exit frame; a connection that
		// stopped without one, or an exit frame the host could not read, is
		// recorded as code 1 with a reason saying which (shell.go). A line
		// carrying the code alone showed a dead supervisor and a command that
		// genuinely failed as the same thing. The signal is here for the same
		// reason: 137 on its own does not say killed.
		how := ""
		if e.Signal != "" {
			how = " on " + e.Signal
		}
		why := ""
		if e.Reason != "" {
			// A shell.end reason can be the guest's own `error` field, which is
			// a guest's choice of bytes going straight to a terminal. An escape
			// sequence here rewrites lines of the replay that have already been
			// printed — a compromised guest editing the audit view as it is
			// read. proto.SafeText exists for exactly this and its own comment
			// names this case (P6-28).
			why = "  · " + proto.SafeText(e.Reason)
		}
		fmt.Printf("%s  %sshell closed   exit %d%s after %d ms%s\n", ts, who, code, how, e.DurationMS, why)
	case recorder.TypeForwardAccept:
		outcome := "carried"
		if e.Reason != "" {
			outcome = "REFUSED  " + proto.SafeText(e.Reason)
		}
		fmt.Printf("%s  %sforward        %s -> guest %d  from %s  %s\n",
			ts, who, "host "+strconv.Itoa(e.Port), e.GuestPort, proto.SafeText(e.Peer), outcome)
	case recorder.TypeRunReview:
		fmt.Printf("%s  %sreview          %s · %d added, %d modified, %d deleted → %s\n",
			ts, who, e.Outcome, e.Added, e.Modified, e.Deleted, proto.SafeText(e.Path))
	case recorder.TypeSessionPause:
		fmt.Printf("%s  %spaused          as %q in %d ms\n", ts, who, proto.SafeText(e.Name), e.DurationMS)
	case recorder.TypeSessionResume:
		why := ""
		if e.Reason != "" {
			why = "  · policy differed: " + proto.SafeText(e.Reason)
		}
		fmt.Printf("%s  %sresumed         %q in %d ms%s\n", ts, who, proto.SafeText(e.Name), e.BootMS, why)
	case recorder.TypeSessionReady:
		// A team member's ready line says how it started, not what booted: the
		// kernel and supervisor are the same for every member and the boot path
		// is not (E2-9, F-D19).
		if e.Agent != "" {
			fmt.Printf("%s  ready           %s%d ms  via=%s image=%s\n",
				ts, who, e.BootMS, proto.SafeText(e.Via), proto.SafeText(e.Image))
			break
		}
		overlay := "overlay=?"
		if e.Overlay != nil {
			overlay = fmt.Sprintf("overlay=%t", *e.Overlay)
		}
		// The boot line is SafeText's own worked example — "where a person
		// reads which walls are around their sandbox" — and until P7-17/F20
		// it was the one line in this switch that did not use it, two cases
		// above one that did.
		fmt.Printf("%s  ready           %d ms  kernel=%s supervisor=%s %s\n",
			ts, e.BootMS, proto.SafeText(e.Kernel), proto.SafeText(e.Supervisor), overlay)
	case recorder.TypeSessionEnd:
		fmt.Printf("%s  session end     %s after %d ms\n", ts, proto.SafeText(e.Reason), e.DurationMS)
	case recorder.TypeCommandStart:
		fmt.Printf("%s  $ %s%s\n", ts, who, proto.SafeText(strings.Join(e.Cmd, " ")))
	case recorder.TypeCommandOutput:
		data, _ := base64.StdEncoding.DecodeString(e.Data)
		prefix := "  | "
		if e.Stream == "stderr" {
			prefix = "  ! "
		}
		// proto.SafeBody rather than SafeText: this is the one field that is
		// legitimately multi-line and legitimately coloured, so quoting the
		// whole blob on one stray byte would cost more than it bought. It
		// keeps \n, \t and SGR colour and replaces everything else — OSC,
		// the screen controls, and a \r that would otherwise drive the cursor
		// back over the fixed prefix below and let the guest print in the
		// host's own voice (P7-17/F20).
		for _, l := range strings.Split(strings.TrimRight(proto.SafeBody(string(data)), "\n"), "\n") {
			fmt.Printf("%s%s%s\n", strings.Repeat(" ", len(ts)), prefix, l)
		}
	case recorder.TypeCommandExit:
		code := -1
		if e.Code != nil {
			code = *e.Code
		}
		extra := ""
		if e.Error != nil {
			extra = fmt.Sprintf("  (%s: %s)", proto.SafeText(e.Error.Kind), proto.SafeText(e.Error.Message))
		}
		fmt.Printf("%s  exit %-3d        %d ms%s\n", ts, code, e.DurationMS, extra)
	case recorder.TypeFileWrite:
		fmt.Printf("%s  write           %s%s  %d bytes  sha256=%s via=%s\n",
			ts, who, proto.SafeText(e.Path), e.Bytes, shortHash(e.SHA256), e.Via)
	case recorder.TypeEgressAttempt:
		verdict := "BLOCKED"
		if e.Allowed != nil && *e.Allowed {
			verdict = "allowed"
		}
		// Who connected, when the record knows. A foreign_peer refusal never
		// parsed a request, so it carries no host and no port and printed as
		// `egress BLOCKED :0` — indistinguishable from an ordinary blocked
		// egress with an empty host, with the one fact that made it worth
		// recording sitting unread in the chain (P7-17/F9, rendered in F20).
		from := ""
		if e.Peer != "" {
			from = "  from " + proto.SafeText(e.Peer)
		}
		fmt.Printf("%s  egress %-7s %s%s:%d  mode=%s %s%s\n", ts, verdict, who,
			proto.SafeText(e.Host), e.Port, proto.SafeText(e.Mode), proto.SafeText(e.Reason), from)
	case recorder.TypeSecretUse:
		fmt.Printf("%s  secret          %s%s -> %s\n", ts, who, proto.SafeText(e.Name), proto.SafeText(e.Host))
	case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
		verb := map[string]string{"send": "->", "ask": "?>", "reply": "<-"}[e.Kind]
		if verb == "" {
			verb = "->"
		}
		what := fmt.Sprintf("%s %s %s", proto.SafeText(e.Agent), verb, proto.SafeText(e.Peer))
		detail := fmt.Sprintf("%s · %d bytes · %s", e.Kind, e.Bytes, shortHash(e.SHA256))
		if e.Type == recorder.TypeTeamRefused {
			fmt.Printf("%s  team REFUSED    %s  %s (%s)\n", ts, what, detail, proto.SafeText(e.Reason))
		} else {
			fmt.Printf("%s  team            %s  %s\n", ts, what, detail)
		}
	case recorder.TypeTeamStore:
		verdict := e.Outcome
		if e.Reason != "" {
			verdict += " · " + proto.SafeText(e.Reason)
		}
		fmt.Printf("%s  team store      %s %s %s  %s\n", ts, proto.SafeText(e.Agent), e.Kind, proto.SafeText(e.Peer), verdict)
	case recorder.TypeTeamSpawn:
		if e.Outcome == "refused" {
			fmt.Printf("%s  team REFUSED    %s may not spawn  (%s)\n", ts, proto.SafeText(e.Agent), proto.SafeText(e.Reason))
		} else {
			fmt.Printf("%s  team %-10s %s by %s\n", ts, e.Kind, proto.SafeText(e.Peer), proto.SafeText(e.Agent))
		}
	case recorder.TypeResourceSummary:
		fmt.Printf("%s  usage           %s%.2f CPU-seconds%s · peak RSS %s (VMM)%s · net %s in / %s out · disk %s written\n",
			ts, who, e.CPUSeconds, quotaSuffix(e), report.HumanKiB(e.PeakRSSKiB),
			capSuffix(e.MemMiB), humanBytes(e.NetInBytes), humanBytes(e.NetOutBytes),
			humanBytes(e.DiskWriteBytes))
	case recorder.TypeResourceTimeout:
		fmt.Printf("%s  timed out       %sthe %s budget of %s expired after %s\n",
			ts, who, e.Budget, time.Duration(e.BudgetMS)*time.Millisecond,
			(time.Duration(e.ElapsedMS) * time.Millisecond).Round(time.Second))
	case recorder.TypeResourceOOM:
		fmt.Printf("%s  OOM-killed      %s%s (pid %d) holding %s of a %d MiB machine\n",
			ts, who, proto.SafeText(e.Comm), e.PID, report.HumanKiB(e.RSSKiB), e.MemMiB)
	case recorder.TypeChannelRefused:
		// A connection to a guest-initiated channel arrived without the
		// session's credential and was refused (audit 2026-09-01, A2/A3).
		// Which channel and why is the whole of what the event holds; the
		// word REFUSED keeps it scannable beside the egress BLOCKED lines
		// it most resembles.
		channel := "unknown"
		switch e.Port {
		case 10100:
			channel = "ready"
		case 10101:
			channel = "events"
		case 10102:
			channel = "team"
		}
		fmt.Printf("%s  REFUSED         %sa connection on the %s channel: %s\n",
			ts, who, channel, proto.SafeText(e.Reason))
	case recorder.TypeSessionPolicy:
		// The ceiling this session ran under, as one greppable line. The full
		// record is in the chain and `kelyfos log --json` prints it; this is
		// the shape a reader scanning a transcript wants — what it was allowed
		// to be, beside what it did.
		parts := []string{}
		if e.VcpuCount > 0 || e.MemMiB > 0 {
			parts = append(parts, fmt.Sprintf("%d vcpu · %d MiB", e.VcpuCount, e.MemMiB))
		}
		if len(e.Allow) > 0 {
			parts = append(parts, "allow "+proto.SafeText(strings.Join(e.Allow, ",")))
		} else {
			parts = append(parts, "no egress")
		}
		if n := len(e.Secrets); n > 0 {
			parts = append(parts, fmt.Sprintf("%d secret(s)", n))
		}
		if e.Workspace != "" {
			parts = append(parts, "workspace "+proto.SafeText(e.Workspace))
		}
		fmt.Printf("%s  policy          %s%s\n", ts, who, strings.Join(parts, " · "))
	case recorder.TypeTeamTopology:
		// Written once at boot, after every agent's own ready/policy pair. The
		// counts are the question a reader has here; the names are one
		// `--json` away.
		parts := []string{fmt.Sprintf("%d agents · %d edges", len(e.Agents), len(e.Edges))}
		if n := len(e.StoreKeys); n > 0 {
			parts = append(parts, fmt.Sprintf("store %d rule(s)", n))
		}
		if e.RecordPayloads != nil && *e.RecordPayloads {
			parts = append(parts, "payloads recorded")
		}
		fmt.Printf("%s  topology        %s\n", ts, strings.Join(parts, " · "))
	case recorder.TypeSessionErasure:
		// Modified counts events touched and RedactedFields counts fields
		// replaced; they are different numbers and an auditor wants both.
		// SHA256 anchors the erased chain to the one it replaced.
		fmt.Printf("%s  erasure         %d event(s), %d field(s) redacted%s  was %s\n",
			ts, e.Modified, e.RedactedFields, reasonSuffix(e.Reason), shortHash(e.SHA256))
	case recorder.TypeSecretWithheld:
		fmt.Printf("%s  secret withheld %s%s -> %s%s\n", ts, who,
			proto.SafeText(e.Name), proto.SafeText(e.Host), reasonSuffix(e.Reason))
	case recorder.TypeSecretScrubbed:
		fmt.Printf("%s  secret scrubbed %s%s out of a response from %s\n", ts, who,
			proto.SafeText(e.Name), proto.SafeText(e.Host))
	case recorder.TypeVMMAction:
		// A state-changing Firecracker API call the host made (audit
		// 2026-09-01, A11) — the pause, resume or snapshot this transcript
		// is entitled to see.
		fmt.Printf("%s  vmm             %s%s\n", ts, who, proto.SafeText(e.Mode))
	case recorder.TypeSecretUnscrubbable:
		// Audit 2026-09-01, A4: a compressed response from a credential-bound
		// origin — the echo suppression could not read the body. The word
		// UNREAD is the honest verb: this is not "nothing happened", it is
		// "the proxy could not check what happened".
		fmt.Printf("%s  UNREAD body     %sa compressed response (%s) from credential-bound %s — "+
			"echo suppression cannot match inside an encoding\n",
			ts, who, proto.SafeText(e.Mode), proto.SafeText(e.Host))
	default:
		// The raw line, through the sanitiser (P7-17/C). This arm is what an
		// event type this build has no case for prints as — a chain written by
		// a newer kelyfos, replayed by an older one, which docs/events.md §3
		// says is a supported thing to do. The line is the JSON as it was
		// written, so every guest-chosen string in it arrives here unfiltered,
		// which is the one place F20's per-event sweep could not reach: it
		// works from the decoded Event and this prints the bytes.
		//
		// SafeText and not SafeBody: a chain line is one line by construction,
		// so there is no newline to preserve, and quoting the whole thing is
		// the right answer for a record nobody has a renderer for yet.
		fmt.Printf("%s  %-15s %s\n", ts, proto.SafeText(e.Type),
			proto.SafeText(strings.TrimSpace(string(line))))
	}
}

// quotaSuffix and capSuffix say what a number was measured against, when there
// was something to measure it against. A receipt that reports consumption
// without the cap it was consumed under is half a receipt.
func quotaSuffix(e recorder.Event) string {
	switch {
	case e.CPUQuota > 0:
		return fmt.Sprintf(" (quota %d%% of one core)", e.CPUQuota)
	case e.VcpuCount > 0:
		return fmt.Sprintf(" across %d core(s), no quota", e.VcpuCount)
	}
	return ""
}

// capSuffix names the machine's RAM beside the VMM's peak resident set without
// claiming the second is a share of the first. It is not: the figure is the
// Firecracker process's own high-water mark, which covers the guest's memory
// *and* whatever the host cached for the block devices it was writing, so it
// routinely exceeds the guest's RAM cap without the guest having exceeded
// anything (docs/events.md).
func capSuffix(memMiB int) string {
	if memMiB <= 0 {
		return ""
	}
	return fmt.Sprintf(" · machine %d MiB", memMiB)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n>>10)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// sessionIsServed reports whether a session belongs to a serve-mcp process
// rather than to a machine or a team. Its session.start says so, which is why
// the reason is written rather than inferred from what the session contains.
func sessionIsServed(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		return false, err
	}
	for _, e := range events {
		if e.Type == recorder.TypeSessionStart {
			return e.Reason == recorder.ReasonServeMCP, nil
		}
	}
	return false, nil
}

// safeEvent returns e with every guest-influenced string cleaned, once, for a
// renderer to draw from (P7-17/F20, second review round).
//
// The first round did this field by field, and the second review found what
// that always finds: `session.start`'s image, arch and kelyfos printed raw two
// lines under a Reason that was SafeText'd; `team.message`'s kind raw beside an
// agent and a peer that were not; and — worst, because it is on nearly every
// line — `e.Agent`, which becomes the `[who]` prefix. `kelyfos watch` was clean
// for the same events, because its code was written later by a different hand.
// Nineteen fields across three renderers is not a list anybody keeps correct.
//
// So it is reflective and it is exclusive: every string and every []string on
// recorder.Event is cleaned EXCEPT the five named below, each for a stated
// reason. A field added to Event later is covered without anybody adding a
// line, which is the property the hand-written version could not have.
//
// SafeText is a no-op on anything that was already fine, so a value used for
// control flow — Kind in a verb lookup, Outcome in a comparison — still
// matches when it is legitimate and stops matching when it is not, which is
// the fail-safe direction.
//
// Its REACH is top-level string and []string fields, and not the nested ones:
// *EvError's Kind and Message, and the struct slices session.policy and
// team.topology carry. That is a boundary rather than a hole today — every
// renderer that draws a nested field routes it through proto.SafeText itself,
// and the F20 sweep probes all of them through all three surfaces — but a line
// added later that prints e.Error.Message directly would be caught by neither
// this function nor that sweep, whose own field walk stops at the same depth.
// Widening both together is the change to make if one ever appears.
func safeEvent(e recorder.Event) recorder.Event {
	rv := reflect.ValueOf(&e).Elem()
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		switch f.Name {
		case "Type":
			// Selects the branch. Quoting it would route every hostile event
			// to the default arm, which prints the raw line — worse, not
			// better. It is compared against constants and never printed
			// except by that arm, which JSON-escapes.
			continue
		case "TS":
			// Sliced as a timestamp (ts[11:23]); quoting it would shift the
			// window. Host-written from the host's own clock.
			continue
		case "Prev", "Hash":
			// Host-computed digests. Hex or empty, never guest text.
			continue
		case "Data":
			// base64 on the wire. The renderers decode it and hand it to
			// proto.SafeBody, which keeps the colour a terminal transcript
			// legitimately carries — SafeText would quote the whole blob.
			continue
		}
		fv := rv.Field(i)
		switch {
		case fv.Kind() == reflect.String:
			fv.SetString(proto.SafeText(fv.String()))
		case fv.Kind() == reflect.Slice && fv.Type().Elem().Kind() == reflect.String:
			// Copied before rewriting, or the signature would be a lie: e is a
			// value, but a value copy shares its slices' backing arrays, so
			// writing through this one reached into the caller's Cmd and Allow.
			// Nothing depended on that — all three callers use only the result
			// and internal/digest retains none of these — but "takes a value,
			// returns a value" has to mean what it says.
			cp := reflect.MakeSlice(fv.Type(), fv.Len(), fv.Len())
			for j := 0; j < fv.Len(); j++ {
				cp.Index(j).SetString(proto.SafeText(fv.Index(j).String()))
			}
			fv.Set(cp)
		}
	}
	return e
}

// reasonSuffix renders an optional reason the way every other arm does, or
// nothing when there is none.
func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return "  (" + proto.SafeText(r) + ")"
}
