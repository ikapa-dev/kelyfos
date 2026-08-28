package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// --- pure decision logic, no filesystem (P7-5, D61) --------------------------

func TestPruneEligible(t *testing.T) {
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	floor := 180 * 24 * time.Hour
	cases := []struct {
		name string
		age  time.Duration
		want bool
	}{
		{"just under the floor", floor - time.Hour, false},
		{"exactly the floor", floor, true},
		{"well past the floor", floor + 365*24*time.Hour, true},
		{"brand new", 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pruneEligible(now.Add(-c.age), now, floor)
			if got != c.want {
				t.Errorf("pruneEligible(age=%s, floor=%s) = %v, want %v", c.age, floor, got, c.want)
			}
		})
	}
}

func TestRetentionFloorDefaultsAndOverrides(t *testing.T) {
	if got := retentionFloor(nil); got != defaultRetentionDays*24*time.Hour {
		t.Errorf("retentionFloor(nil) = %s, want the %d-day default", got, defaultRetentionDays)
	}
	if got := retentionFloor(&config.Config{}); got != defaultRetentionDays*24*time.Hour {
		t.Errorf("retentionFloor(no [sessions]) = %s, want the %d-day default", got, defaultRetentionDays)
	}
	cfg := &config.Config{Sessions: &config.Sessions{RetentionDays: 30}}
	if got := retentionFloor(cfg); got != 30*24*time.Hour {
		t.Errorf("retentionFloor(retention_days=30) = %s, want 30 days", got)
	}
	// A written-but-zero retention_days is not distinguishable from absent
	// (internal/config's own zero-means-not-set convention), so it also
	// gets the default rather than "no floor at all."
	zero := &config.Config{Sessions: &config.Sessions{RetentionDays: 0}}
	if got := retentionFloor(zero); got != defaultRetentionDays*24*time.Hour {
		t.Errorf("retentionFloor(retention_days=0) = %s, want the %d-day default", got, defaultRetentionDays)
	}
}

// --- guards that touch the filesystem -----------------------------------

func TestSessionIsLive(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())

	if sessionIsLive("nothing-here", map[string]bool{}, map[string]bool{}) {
		t.Error("a session with no run directory and no paused-session reference reads as live")
	}

	runningSandbox(t, sandbox.State{ID: "sb-live", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})
	if !sessionIsLive("sb-live", map[string]bool{}, map[string]bool{}) {
		t.Error("a session with a run directory did not read as live")
	}

	if !sessionIsLive("sb-paused", map[string]bool{"sb-paused": true}, map[string]bool{}) {
		t.Error("a session named by a paused session's own metadata did not read as live")
	}

	// P7-13/F1: a team's own chain (or a serve-mcp audit chain) is opened
	// under an id that names no sandbox's own run directory, so neither of
	// the two checks above ever sees it — only RunningSessions (a live
	// sandbox's own RecordSession() naming this id) can.
	if !sessionIsLive("team-chain-id", map[string]bool{}, map[string]bool{"team-chain-id": true}) {
		t.Error("a session named by a live sandbox's RecordSession(), but with no run directory of its own, did not read as live")
	}
}

func TestLivePausedSessionsReadsTheSessionField(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	dir := namedDir("before-lunch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := NamedMeta{Name: "before-lunch", Sandbox: "sb1", Session: "sess-abc", PausedAt: time.Now()}
	blob, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(namedMeta(dir), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	live, err := livePausedSessions()
	if err != nil {
		t.Fatal(err)
	}
	if !live["sess-abc"] {
		t.Errorf("live = %v, want sess-abc marked live from the paused session's own metadata", live)
	}
}

// --- recorded-session fixtures for the end-to-end tests ----------------------

// writeRecordedSession builds a real, hash-chained session under
// KELYFOS_CACHE/sessions/<id>, aged to look like its own events.jsonl was
// last written ageDays ago — what a session prune now actually considers
// (S2: events.jsonl's own mtime, not the directory's, since appending never
// advances a directory's own mtime on POSIX). Content is real enough to be
// erasable (Data on a command.output).
func writeRecordedSession(t *testing.T, id string, ageDays int) {
	t.Helper()
	root := sandbox.Root()
	rec, err := recorder.Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeCommandOutput, Data: "hello from " + id}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "shutdown"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour)
	if err := os.Chtimes(recorder.Path(root, id), old, old); err != nil {
		t.Fatal(err)
	}
	// The directory itself is aged too, so a test that still looks at it
	// for any reason sees a consistent picture — prune no longer reads
	// this, but nothing should depend on it disagreeing with the file.
	dir := filepath.Join(recorder.SessionsDir(root), id)
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
}

func sessionExists(t *testing.T, id string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(recorder.SessionsDir(sandbox.Root()), id))
	return err == nil
}

// isolateFromAmbientPolicy points the working directory at an empty temp
// directory so loadPolicyAt("")'s walk-up finds nothing — this repository
// carries its own kelyfos.toml at its root (for the agent working on
// KelyfOS itself to run under), and without this a test run from inside
// the repository would silently pick that up instead of genuinely testing
// "no policy found." It has no [sessions] section today, so every test
// below would still pass either way, but that is the ambient repo's
// business, not this test's to depend on.
func isolateFromAmbientPolicy(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
}

func TestSessionsPruneDeletesOnlyPastTheFloor(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "old-enough", 200)
	writeRecordedSession(t, "too-new", 10)

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if sessionExists(t, "old-enough") {
		t.Error("a session past the default 180-day floor was not pruned")
	}
	if !sessionExists(t, "too-new") {
		t.Error("a session inside the floor was pruned")
	}
}

// P7-13/F1: prune shared sessionIsLive's two original checks with erase, but
// not the third erase's own review already found it needed (B1) — a team's
// chain (or a serve-mcp audit chain) is opened under an id that names no
// sandbox's own run directory, so hasLiveRunDir never sees it live no matter
// how recently a member sandbox wrote to it. Past the retention floor with a
// live member sandbox still attached, prune would delete the directory out
// from under that writer — the same silent-audit-loss failure B1 named,
// just left open on this path.
func TestSessionsPruneSkipsALiveTeamsChain(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "team-chain-id", 200) // well past the default floor
	runningSandbox(t, sandbox.State{ID: "member-own-id", Session: "team-chain-id",
		PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if !sessionExists(t, "team-chain-id") {
		t.Fatal("prune deleted a team's own chain while a live member sandbox was still writing into it")
	}
}

// P7-13: a `kelyfos serve-mcp` process's own audit session names no
// sandbox's own run directory and no sandbox's RunningSessions() entry —
// running[id], the check the previous fix added, cannot see it either. This
// was live-reproduced against the real fix above: the process kept running
// with its own session directory deleted out from under it by prune, no
// error anywhere. openAudit's marker file is the fourth, and last, check.
func TestSessionsPruneSkipsALiveServeMCPAuditChain(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "audit-chain-id", 200) // well past the default floor
	if err := os.MkdirAll(auditMarkerDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditMarkerPath("audit-chain-id"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if !sessionExists(t, "audit-chain-id") {
		t.Fatal("prune deleted a live serve-mcp process's own audit chain")
	}
}

// Once the marker is gone — the same shutdown path closeAudit takes — the
// session prunes normally, same as any other ended session past the floor.
func TestSessionsPruneDeletesAServeMCPAuditChainOnceItsMarkerIsGone(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "audit-chain-id", 200)

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if sessionExists(t, "audit-chain-id") {
		t.Fatal("a session with no marker, past the floor, was not pruned")
	}
}

func TestSessionsEraseRefusesALiveServeMCPAuditChain(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "audit-chain-id", 0)
	if err := os.MkdirAll(auditMarkerDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditMarkerPath("audit-chain-id"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := sessionsErase([]string{"-reason", "test", "audit-chain-id"}); err == nil {
		t.Fatal("erase accepted a live serve-mcp process's own audit chain")
	}
	blob, err := os.ReadFile(recorder.Path(sandbox.Root(), "audit-chain-id"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if events[len(events)-1].Type == recorder.TypeSessionErasure {
		t.Fatal("the serve-mcp audit chain was erased despite its live marker")
	}
}

// openAudit/closeAudit are the two places this marker is actually
// maintained in production; this exercises them directly rather than only
// the sessions.go side of the contract the tests above assume.
func TestOpenAuditMarksTheSessionLiveAndCloseAuditClearsIt(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := &hostServer{arch: "aarch64"}

	if err := s.openAudit(); err != nil {
		t.Fatal(err)
	}
	if !hasLiveAuditMarker(s.auditID) {
		t.Fatal("openAudit did not mark its own session live")
	}

	s.closeAudit()
	if hasLiveAuditMarker(s.auditID) {
		t.Fatal("closeAudit did not clear its own session's live marker")
	}
}

// TestSessionsPruneAgesByEventsFileNotDirectory is S2's direct repro:
// appending to events.jsonl does not advance its parent directory's own
// mtime on POSIX (only creating or removing a directory ENTRY does), so
// ageing by the directory aged a session from when it was first created —
// session START — while docs/retention.md described "twelve months from
// session close." Here the directory is deliberately left with a FRESH
// mtime (as it always was, in practice, on every real session prune ever
// ran against) while events.jsonl itself is aged past the floor — proving
// prune follows the file, not the directory.
func TestSessionsPruneAgesByEventsFileNotDirectory(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "old-file-fresh-dir", 200)

	// Un-age the directory back to now, the way it would actually be after
	// a real session: nothing ever touches a session directory's own mtime
	// again after it is created, so on a real machine it stays at creation
	// time forever while events.jsonl keeps moving forward with every
	// write. This simulates that gap directly rather than relying on the
	// OS to reproduce it inside a single test run.
	dir := filepath.Join(recorder.SessionsDir(sandbox.Root()), "old-file-fresh-dir")
	now := time.Now()
	if err := os.Chtimes(dir, now, now); err != nil {
		t.Fatal(err)
	}

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if sessionExists(t, "old-file-fresh-dir") {
		t.Error("a session whose events.jsonl is 200 days old was not pruned, even though its " +
			"directory's own mtime (never aged by the age-by-directory bug) reads as fresh")
	}
}

func TestSessionsPruneDryRunDeletesNothing(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "old-enough", 200)

	if err := sessionsPrune([]string{"-dry-run"}); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if !sessionExists(t, "old-enough") {
		t.Error("-dry-run deleted a session")
	}
}

func TestSessionsPruneRespectsAPolicysRetentionFloor(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "thirty-five-days", 35)

	dir := t.TempDir()
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte("[sessions]\nretention_days = 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sessionsPrune([]string{"-policy", path}); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if sessionExists(t, "thirty-five-days") {
		t.Error("a session past a policy's own 30-day floor was not pruned")
	}
}

func TestSessionsPruneSkipsAPausedSessionsChain(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "still-paused", 400) // ancient, and would prune otherwise

	dir := namedDir("keepsake")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := NamedMeta{Name: "keepsake", Sandbox: "still-paused", Session: "still-paused", PausedAt: time.Now()}
	blob, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(namedMeta(dir), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if !sessionExists(t, "still-paused") {
		t.Error("prune deleted a paused session's own chain, which would break its resume")
	}
}

func TestSessionsPruneSkipsALiveRunDirectory(t *testing.T) {
	isolateFromAmbientPolicy(t)
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "looks-live", 400)
	runningSandbox(t, sandbox.State{ID: "looks-live", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})

	if err := sessionsPrune(nil); err != nil {
		t.Fatalf("sessionsPrune: %v", err)
	}
	if !sessionExists(t, "looks-live") {
		t.Error("prune deleted a session with a run directory that looked live")
	}
}

// --- kelyfos sessions erase, through the CLI door ----------------------------

func TestSessionsEraseThroughTheCLI(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "erase-me", 0)

	if err := sessionsErase([]string{"-reason", "test erasure", "erase-me"}); err != nil {
		t.Fatalf("sessionsErase: %v", err)
	}
	blob, err := os.ReadFile(recorder.Path(sandbox.Root(), "erase-me"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recorder.Verify(bytes.NewReader(blob)); err != nil {
		t.Fatalf("chain does not verify after erasure through the CLI: %v", err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if events[len(events)-1].Type != recorder.TypeSessionErasure {
		t.Errorf("last event is %q, want %q", events[len(events)-1].Type, recorder.TypeSessionErasure)
	}
}

// TestSessionsEraseAcceptsTheIDBeforeTheFlag is S4: kelyfos verify already
// takes flags on either side of its path argument (host/flags.go's
// parseAround), and erase now uses the same helper rather than a plain
// fs.Parse, so `erase <id> -reason ...` — the order Go's own flag package
// would otherwise silently misparse as two positional arguments — works
// the same as `erase -reason ... <id>`.
func TestSessionsEraseAcceptsTheIDBeforeTheFlag(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "erase-me", 0)

	if err := sessionsErase([]string{"erase-me", "-reason", "test erasure"}); err != nil {
		t.Fatalf("sessionsErase with the id before -reason: %v", err)
	}
	blob, err := os.ReadFile(recorder.Path(sandbox.Root(), "erase-me"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recorder.Verify(bytes.NewReader(blob)); err != nil {
		t.Fatalf("chain does not verify after erasure through the CLI: %v", err)
	}
}

// TestSessionsEraseRefusesExtraPositionalArgs is S4's second half: before
// this fix, `erase -reason x a b` silently erased only "a" and said nothing
// about "b" — parseAround makes both positionals visible, and erase now
// refuses rather than guessing which one was meant.
func TestSessionsEraseRefusesExtraPositionalArgs(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "erase-me", 0)
	writeRecordedSession(t, "erase-me-too", 0)

	if err := sessionsErase([]string{"-reason", "test", "erase-me", "erase-me-too"}); err == nil {
		t.Fatal("erase with two positional ids was accepted")
	}
	blob, err := os.ReadFile(recorder.Path(sandbox.Root(), "erase-me"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := recorder.Verify(bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if events[len(events)-1].Type == recorder.TypeSessionErasure {
		t.Fatal("erase with extra positional args still erased the first one silently")
	}
}

func TestSessionsEraseRefusesWithNoReason(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "erase-me", 0)
	if err := sessionsErase([]string{"erase-me"}); err == nil {
		t.Fatal("erase with no -reason was accepted")
	}
}

func TestSessionsEraseRefusesAPausedSession(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "paused-chain", 0)

	dir := namedDir("keepsake")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := NamedMeta{Name: "keepsake", Sandbox: "paused-chain", Session: "paused-chain", PausedAt: time.Now()}
	blob, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(namedMeta(dir), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	err = sessionsErase([]string{"-reason", "test", "paused-chain"})
	if err == nil {
		t.Fatal("erase accepted a currently paused session's own chain")
	}
}

func TestSessionsEraseRefusesALiveRunDirectory(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "live-chain", 0)
	runningSandbox(t, sandbox.State{ID: "live-chain", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})

	if err := sessionsErase([]string{"-reason", "test", "live-chain"}); err == nil {
		t.Fatal("erase accepted a session with a live-looking run directory")
	}
}

// TestSessionsEraseRefusesALiveTeamsChain is B1's second gap, closed: a
// team's own chain is opened under an id from sandbox.NewID() that is
// never any sandbox's own id (host/team.go's raiseTeam), so no run
// directory is ever named for it and hasLiveRunDir alone cannot see the
// team is still running — only each MEMBER sandbox's own run directory
// exists, with that member's State.Session naming the team's chain. This
// simulates exactly that shape: a recorded chain under a team-style id,
// and a live sandbox whose own id differs but whose Session names that
// chain, the way host/team.go actually wires up a member.
func TestSessionsEraseRefusesALiveTeamsChain(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRecordedSession(t, "team-chain-id", 0)
	runningSandbox(t, sandbox.State{ID: "member-own-id", Session: "team-chain-id",
		PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})

	if err := sessionsErase([]string{"-reason", "test", "team-chain-id"}); err == nil {
		t.Fatal("erase accepted a team's own chain while a live member sandbox was still writing into it")
	}
	blob, err := os.ReadFile(recorder.Path(sandbox.Root(), "team-chain-id"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if events[len(events)-1].Type == recorder.TypeSessionErasure {
		t.Fatal("the team's chain was erased despite a live member sandbox writing into it")
	}
}
