package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
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
