package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

func policyFrom(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), config.FileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the test's own policy does not parse: %v", err)
	}
	return cfg
}

// "The policy changed" tells somebody to go and diff two files. Naming the
// differences tells them whether they care, which is the whole point of the
// message (docs/qol.md §1.2).
func TestAResumeNamesWhatChanged(t *testing.T) {
	frozen := policyFrom(t, "[sandbox]\nimage = \"dev\"\nallow = [\"example.com\"]\n\n[resources]\ncpus = 2\nmem = \"512M\"\n")
	current := policyFrom(t, "[sandbox]\nimage = \"dev\"\nallow = [\"api.github.com\"]\n\n[resources]\ncpus = 4\nmem = \"512M\"\n")

	got := strings.Join(policyDifference(frozen, current), "; ")
	for _, want := range []string{"cpus 2 → 4", "allow gained api.github.com", "allow lost example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("the difference does not mention %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "mem") {
		t.Errorf("a value that did not change was reported as a difference:\n%s", got)
	}

	// The same file twice is no difference at all, whatever its formatting.
	same := policyFrom(t, "[resources]\ncpus = 2\n\n# a comment that changes nothing\nmem = \"512M\"\n")
	other := policyFrom(t, "[resources]\nmem  = \"512M\"\ncpus = 2\n")
	if diffs := policyDifference(same, other); len(diffs) > 0 {
		t.Errorf("reordering keys and adding a comment read as a change: %v", diffs)
	}
}

// A resume runs the frozen policy, so it must not be a way to carry an old
// ceiling past a new one — the hole E4-2 found in sandbox_restore (F-D39).
func TestAResumeCannotOutrunTheCurrentCeiling(t *testing.T) {
	frozen := policyFrom(t, "[sandbox]\nallow = [\"example.com\"]\n\n[resources]\ncpus = 8\nmem = \"2G\"\n")
	current := policyFrom(t, "[sandbox]\nallow = [\"example.com\"]\n\n[resources]\ncpus = 2\nmem = \"2G\"\n")

	err := frozenFitsCurrent("mig", frozen, current)
	if err == nil {
		t.Fatal("an 8 vcpu frozen policy resumed under a 2 vcpu ceiling")
	}
	for _, want := range []string{"cpus = 8", "ceiling of 2", "kelyfos.toml:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// Memory, and the allowlist, on the same rule.
	tight := policyFrom(t, "[sandbox]\nallow = [\"example.com\"]\n\n[resources]\ncpus = 8\nmem = \"512M\"\n")
	if frozenFitsCurrent("mig", frozen, tight) == nil {
		t.Error("a 2 GiB frozen policy resumed under a 512 MiB ceiling")
	}
	narrowed := policyFrom(t, "[sandbox]\nallow = [\"api.github.com\"]\n\n[resources]\ncpus = 8\nmem = \"2G\"\n")
	err = frozenFitsCurrent("mig", frozen, narrowed)
	if err == nil {
		t.Fatal("a frozen allowlist entry the project no longer permits was resumed")
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("the refusal does not name the domain:\n%v", err)
	}

	// And a policy that fits is not refused.
	if err := frozenFitsCurrent("mig", frozen, frozen); err != nil {
		t.Errorf("a policy identical to itself was refused: %v", err)
	}
	// With no policy in force there is no ceiling to exceed.
	if err := frozenFitsCurrent("mig", frozen, nil); err != nil {
		t.Errorf("with no current policy there is nothing to exceed, but: %v", err)
	}
}

// A session name becomes a directory, and `pause --as` is a thing a script can
// write as easily as a person.
func TestASessionNameCannotWalkOut(t *testing.T) {
	for _, bad := range []string{"", "..", "../evil", "a/b", ".hidden"} {
		if err := validSessionName(bad); err == nil {
			t.Errorf("%q was accepted as a session name", bad)
		}
	}
	if err := validSessionName(""); err == nil || !strings.Contains(err.Error(), "--as") {
		t.Errorf("an empty name does not say how to give one: %v", err)
	}
	for _, good := range []string{"before-the-migration", "v1.2_final", "p1"} {
		if err := validSessionName(good); err != nil {
			t.Errorf("%q is a reasonable name and was refused: %v", good, err)
		}
	}
}

// runningSandbox writes the state file `kelyfos pause` reads, under a cache
// root belonging to this test alone. Nothing boots and nothing needs to: the
// refusal below happens before the snapshot is taken, which is the point of
// making it there.
func runningSandbox(t *testing.T, st sandbox.State) {
	t.Helper()
	dir := sandbox.RunDirOf(st.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sandbox.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The two ends of a pause have to agree about what can come back. `resume`
// refuses a session whose snapshot recorded a NIC, and the snapshot layer
// records one for every machine that had a TAP — so a pause that does not ask
// the same question stops the machine, writes the whole session, and prints a
// resume command guaranteed to refuse. There is no second way in either:
// `snapshot restore` reads snapshots/<name>, and what a pause writes is
// named/<name>.
func TestAPauseRefusesTheMachineNoResumeCouldOpen(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	runningSandbox(t, sandbox.State{ID: "sb-egress", PID: os.Getpid(), Arch: "aarch64",
		Flavor: "dev", TAP: "kf0", Allow: []string{"example.com"}})

	err := pauseCmd([]string{"--sandbox", "sb-egress", "--as", "before-the-migration"})
	if err == nil {
		t.Fatal("a sandbox with egress was paused into a session nothing can bring back")
	}
	// What was in force, what state the machine is in, and the way that does
	// work — a refusal naming none of the three is a dead end with prose.
	for _, want := range []string{"example.com", "still running",
		"kelyfos snapshot save", "kelyfos snapshot restore", "before-the-migration"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "kelyfos resume before-the-migration") {
		t.Errorf("the refusal offers the one command that cannot work:\n%v", err)
	}
	// Refused before anything moved: no session on disk, and no marker telling
	// the run that owns this machine to skip its sync-back for ever.
	if _, err := os.Stat(namedDir("before-the-migration")); !os.IsNotExist(err) {
		t.Errorf("the refused pause left a stored session behind at %s", namedDir("before-the-migration"))
	}
	if _, err := os.Stat(filepath.Join(sandbox.RunDirOf("sb-egress"), "paused")); !os.IsNotExist(err) {
		t.Error("the refused pause left the pause marker down, so the machine's own run would skip its sync-back")
	}

	// A machine with no NIC is the machine pause is for, and gets past this to
	// the snapshot it cannot take without a live VMM — which is a different
	// refusal, and proves this one did not fire.
	runningSandbox(t, sandbox.State{ID: "sb-quiet", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})
	err = pauseCmd([]string{"--sandbox", "sb-quiet", "--as", "t1"})
	if err == nil || strings.Contains(err.Error(), "egress") {
		t.Errorf("a sandbox with no network was refused a pause: %v", err)
	}
}
