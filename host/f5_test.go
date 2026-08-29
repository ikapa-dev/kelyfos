package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P7-17/F5 — MCP client configuration files were created world-readable.
//
//	os.MkdirAll(filepath.Dir(path), 0o755)
//	os.WriteFile(path, updated, 0o644)
//
// Two of the six targets live under $HOME and are files that commonly grow
// credentials later: ~/.codex/config.toml and ~/.gemini/settings.json. Nothing
// in them is secret the moment `kelyfos connect` writes them; the exposure is
// the case where KelyfOS is the first thing to create the file — the common
// case for a fresh setup — because os.WriteFile only applies perm on creation,
// and the client that later writes an API key into it keeps the mode it found.
//
// The rule is by path prefix and not by client name, so a client added later
// inherits it without anybody remembering to.

func f5Cmd() command {
	return command{Bin: "/usr/local/bin/kelyfos", Args: []string{"serve-mcp", "--policy", "/p/kelyfos.toml"}}
}

// mode of a path, as a bare permission bit set.
func f5Mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// A file under the user's home is owner-only, and so is every directory made
// on the way to it.
func TestF5_AConfigUnderHomeIsOwnerOnly(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	for _, name := range []string{"codex", "gemini"} {
		t.Run(name, func(t *testing.T) {
			c, ok := findClient(name)
			if !ok {
				t.Fatalf("no client named %q", name)
			}
			path := c.Path(project, home)
			if !strings.HasPrefix(path, home) {
				t.Fatalf("%s does not write under home; this fixture is checking the wrong thing", name)
			}
			if err := writeTo(c, path, home, f5Cmd()); err != nil {
				t.Fatal(err)
			}
			if got := f5Mode(t, path); got != 0o600 {
				t.Errorf("%s wrote %s as %04o, want 0600 — this file grows an API key later", name, path, got)
			}
			// Every directory between home and the file, too: a 0755 dir over
			// a 0600 file still tells everyone the file is there and what it
			// is called.
			for dir := filepath.Dir(path); dir != home && dir != "/"; dir = filepath.Dir(dir) {
				if got := f5Mode(t, dir); got != 0o700 {
					t.Errorf("%s created %s as %04o, want 0700", name, dir, got)
				}
			}
		})
	}
}

// A project-local file is meant to be committed and shared, so it keeps the
// mode the process umask gives everything else this CLI writes.
func TestF5_AProjectLocalConfigStaysReadable(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	for _, name := range []string{"claude-code", "cursor", "vscode", "junie"} {
		t.Run(name, func(t *testing.T) {
			c, _ := findClient(name)
			path := c.Path(project, home)
			if strings.HasPrefix(path, home) {
				t.Fatalf("%s writes under home; this fixture is checking the wrong thing", name)
			}
			if err := writeTo(c, path, home, f5Cmd()); err != nil {
				t.Fatal(err)
			}
			want := createMode() & 0o666
			if got := f5Mode(t, path); got != want {
				t.Errorf("%s wrote %s as %04o, want %04o — a committed file should not be owner-only",
					name, path, got, want)
			}
		})
	}
}

// Never lower an existing file's mode. Somebody who tightened their own
// configuration file, or a client that created it 0600 itself, must not have
// that undone by `kelyfos connect`.
func TestF5_AnExistingStricterModeIsKept(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	// A project-local file the user already made owner-only. The prefix rule
	// says 0644 for this path; the Stat rule says keep the stricter.
	c, _ := findClient("claude-code")
	path := c.Path(project, home)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeTo(c, path, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	if got := f5Mode(t, path); got != 0o600 {
		t.Errorf("an existing 0600 file came back as %04o; kelyfos connect widened it", got)
	}

	// And removal keeps it too — the same write, the other direction.
	if err := removeFrom(c, path, home); err != nil {
		t.Fatal(err)
	}
	if got := f5Mode(t, path); got != 0o600 {
		t.Errorf("removing kelyfos widened the file to %04o", got)
	}
}

// A file that already exists with a more permissive mode than the rule asks
// for is a file the user chose; the rule tightens it only where it is the one
// creating the file. Under home it is tightened anyway, because that is the
// whole finding.
func TestF5_AnExistingHomeConfigIsTightened(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	c, _ := findClient("gemini")
	path := c.Path(project, home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeTo(c, path, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	if got := f5Mode(t, path); got != 0o600 {
		t.Errorf("a world-readable file under home came back as %04o, want 0600", got)
	}
}

// The write is a read-modify-write of a file another program may be editing,
// so it goes to a sibling temp file, is fsynced, and is renamed over the
// target. What this pins is the observable half: nothing is left behind, and a
// write that fails leaves the previous content exactly as it was.
func TestF5_TheWriteIsAtomicAndLeavesNoDebris(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	c, _ := findClient("cursor")
	path := c.Path(project, home)

	if err := writeTo(c, path, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("the write left %s beside the target", e.Name())
		}
	}

	// A file that will not parse is refused before anything is written, and
	// the original survives byte for byte.
	before := []byte("this is not JSON\n")
	if err := os.WriteFile(path, before, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeTo(c, path, home, f5Cmd()); err == nil {
		t.Fatal("a file that is not JSON was rewritten anyway")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused write changed the file:\n  was %q\n  now %q", before, after)
	}
	entries, _ = os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("the refused write left %s beside the target", e.Name())
		}
	}
}

// The rule is by prefix, so a client added later inherits it. This walks the
// real catalog rather than a list restated here: a seventh client writing to
// ~/.something/config.json is covered on the day it is added.
func TestF5_EveryHomeScopedClientInTheCatalogIsOwnerOnly(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	sawHome, sawProject := 0, 0
	for _, c := range clients() {
		path := c.Path(project, home)
		if err := writeTo(c, path, home, f5Cmd()); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got := f5Mode(t, path)
		if strings.HasPrefix(path, home+string(filepath.Separator)) {
			sawHome++
			if got != 0o600 {
				t.Errorf("%s writes %s under home as %04o, want 0600", c.Name, path, got)
			}
			continue
		}
		sawProject++
		if got != createMode()&0o666 {
			t.Errorf("%s writes %s as %04o, want %04o", c.Name, path, got, createMode()&0o666)
		}
	}
	// Both sides of the rule were actually exercised, or this test proves
	// only that the catalog is not empty.
	if sawHome == 0 || sawProject == 0 {
		t.Fatalf("the catalog exercised %d home-scoped and %d project-local clients; both must be non-zero",
			sawHome, sawProject)
	}
}

// P7-17/F5, second review round, two corrections.
//
// 1. writeConfigAtomic fsynced the FILE and not the containing DIRECTORY, so a
//    power cut could lose the rename. The stated property still held — the old
//    file survives — but the comment claimed durability the code did not
//    provide, and a comment that overstates is how the next reader stops
//    checking.
// 2. underHome was a textual prefix, so a project-local `.cursor` that is a
//    symlink into $HOME got the project mode rather than 0600. A path rule that
//    a symlink walks around is the same defect F18 found in the extractor and
//    F21 fixed in the workspace and plugin scopes.

func TestF5_APathSymlinkedIntoHomeIsTreatedAsBeingInHome(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	// The project's .cursor is a symlink into the user's home, which is how
	// somebody shares one MCP configuration across checkouts.
	real := filepath.Join(home, "shared-cursor")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, ".cursor")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}

	path := filepath.Join(link, "mcp.json")
	if !underHome(path, home) {
		t.Fatal("a path that resolves into $HOME was not treated as being under it")
	}

	c, _ := findClient("cursor")
	if err := writeTo(c, path, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	if got := f5Mode(t, path); got != 0o600 {
		t.Errorf("a config written through a symlink into $HOME is %04o, want 0600", got)
	}
}

// And the ordinary cases still decide the ordinary way: a real project path is
// project-local, a real home path is home.
func TestF5_UnderHomeStillAnswersTheSimpleCases(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if underHome(filepath.Join(project, ".mcp.json"), home) {
		t.Error("a project-local path was treated as being under $HOME")
	}
	if !underHome(filepath.Join(home, ".codex", "config.toml"), home) {
		t.Error("a path under $HOME was not treated as being under it")
	}
	// A sibling directory whose name merely starts with the home path is not
	// under it — the textual-prefix trap in the other direction.
	if underHome(home+"-other/x", home) {
		t.Error("a sibling directory sharing the home prefix was treated as being under $HOME")
	}
}
