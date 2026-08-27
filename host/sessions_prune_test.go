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

	if sessionIsLive("nothing-here", map[string]bool{}) {
		t.Error("a session with no run directory and no paused-session reference reads as live")
	}

	runningSandbox(t, sandbox.State{ID: "sb-live", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})
	if !sessionIsLive("sb-live", map[string]bool{}) {
		t.Error("a session with a run directory did not read as live")
	}

	if !sessionIsLive("sb-paused", map[string]bool{"sb-paused": true}) {
		t.Error("a session named by a paused session's own metadata did not read as live")
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
// KELYFOS_CACHE/sessions/<id>, aged to look like it was last touched
// ageDays ago, the way a session prune considers would actually look on
// disk. Content is real enough to be erasable (Data on a command.output).
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
	dir := filepath.Join(recorder.SessionsDir(root), id)
	old := time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour)
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
