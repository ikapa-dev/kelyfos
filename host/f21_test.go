package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/config"
)

// P7-17/F21, the host half: the trust check has to be on the path every door
// takes, and what a policy file reaches has to be visible before anything
// boots.

func f21Chdir(t *testing.T, dir string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
}

// Every door in the CLI reaches a policy file through loadPolicyAt, so that is
// where the check goes — not at each of the eight callers, which is the same
// mistake F7 is about.
func TestF21_ADiscoveredPolicyAnybodyCanWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte("[sandbox]\nimage = \"dev\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f21Chdir(t, sub)

	if _, err := loadPolicy(); err != nil {
		t.Fatalf("an ordinary policy found by walking up was refused: %v", err)
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	_, err := loadPolicy()
	if err == nil {
		t.Fatal("a world-writable policy found by walking up was loaded anyway")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "chmod") {
		t.Errorf("the refusal does not name the file and the fix: %v", err)
	}

	// --policy is the escape hatch for ownership and NOT for writability: a
	// file anybody can rewrite is not made safe by being named.
	if _, err := loadPolicyAt(path); err == nil {
		t.Error("--policy loaded a world-writable file")
	}
}

// A workspace the file names outside its own directory tree is refused, because
// that directory is packed into the guest and synced back over on shutdown — a
// cloned repository does not get to name your home directory. Typing the same
// value on the command line is the escape hatch, because then it is your
// decision and not the file's.
func TestF21_AWorkspaceOutsideThePolicysTreeIsRefused(t *testing.T) {
	project := t.TempDir()
	elsewhere := t.TempDir()
	cfgPath := filepath.Join(project, config.FileName)

	inside := filepath.Join(project, "src")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name string
		ws   string
		want bool // want an error
	}{
		{"the project directory itself", project, false},
		{"a subdirectory", inside, false},
		{"a relative subdirectory", "src", false},
		{"somewhere else entirely", elsewhere, true},
		{"a relative path that climbs out", "../" + filepath.Base(elsewhere), true},
		{"the operator's home", "/root", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := checkWorkspaceScope(cfgPath, c.ws)
			if c.want && err == nil {
				t.Errorf("workspace %q outside %s was accepted", c.ws, project)
			}
			if !c.want && err != nil {
				t.Errorf("workspace %q inside %s was refused: %v", c.ws, project, err)
			}
			if c.want && err != nil {
				if !strings.Contains(err.Error(), "--workspace") {
					t.Errorf("the refusal does not name the escape hatch: %v", err)
				}
			}
		})
	}
}

// And the origin line: what the file reaches, said out loud before anything
// boots. A policy that names a host directory, a plugin directory and a secret
// bound to a domain must say all three.
func TestF21_ThePolicySaysWhatItReachesBeforeAnythingBoots(t *testing.T) {
	project := t.TempDir()
	cfgPath := filepath.Join(project, config.FileName)
	body := "[sandbox]\nimage = \"dev\"\nworkspace = \"src\"\nallow = [\"api.github.com\"]\n" +
		"secrets = [\"GITHUB_TOKEN@api.github.com\"]\n\n" +
		"[[plugin]]\nname = \"tools\"\npath = \"plug\"\ncommand = \"./server\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	printPolicyReach(&b, cfg)
	got := b.String()

	for _, want := range []string{
		cfgPath,
		filepath.Join(project, "src"),
		filepath.Join(project, "plug"),
		"GITHUB_TOKEN",
		"api.github.com",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the policy origin block does not name %q:\n%s", want, got)
		}
	}
	// The secret's VALUE is never read here and never printed. Only its name
	// and the domain it is bound to — and the block says both even when the
	// variable is not set on this host, which is exactly the moment somebody
	// is about to be asked to set one.
	if os.Getenv("GITHUB_TOKEN") != "" {
		t.Skip("GITHUB_TOKEN is set in this environment; the unset case is the one under test")
	}
	if !strings.Contains(got, "$GITHUB_TOKEN of your environment") {
		t.Errorf("the origin block does not say the secret is read from the environment:\n%s", got)
	}
	if strings.Contains(got, "GITHUB_TOKEN=") {
		t.Errorf("the origin block looks like it printed a value:\n%s", got)
	}
}

// A policy that reaches nothing outside itself says so in one line rather than
// printing an empty list of headings.
func TestF21_APolicyThatReachesNothingIsQuiet(t *testing.T) {
	project := t.TempDir()
	cfgPath := filepath.Join(project, config.FileName)
	if err := os.WriteFile(cfgPath, []byte("[sandbox]\nimage = \"dev\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	printPolicyReach(&b, cfg)
	got := b.String()
	if strings.Count(got, "\n") != 1 {
		t.Errorf("a policy that reaches nothing printed %d lines:\n%s", strings.Count(got, "\n"), got)
	}
	if !strings.Contains(got, cfgPath) {
		t.Errorf("the one line does not name the file:\n%s", got)
	}
}
