package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P7-17/B1 — the regression F5's own fix introduced.
//
// F5 moved `kelyfos connect` from os.WriteFile to a temp-file-plus-rename,
// which is right: this is a read-modify-write of a file another program may be
// editing, and a rename is the only atomic replacement available. What it did
// not account for is that os.WriteFile FOLLOWS a leaf symlink and a rename
// REPLACES one. A dotfiles-managed ~/.codex/config.toml — stow, chezmoi, a
// hand-made link into a repository — was quietly turned into a plain file, and
// the copy the user version-controls stopped being the copy the client reads.
//
// And it inverted F5 at the same time, by way of underHome: a leaf link under
// $HOME pointing outside it resolved outside, so the file was judged
// project-local and created 0644 — world-readable, under $HOME, at the exact
// path F5 exists to protect.

// b1Link makes dir/name a symlink to target and skips if the platform will not.
func b1Link(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
}

// isLink reports whether path is still a symlink.
func isLink(t *testing.T, path string) bool {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %s: %v", path, err)
	}
	return fi.Mode()&os.ModeSymlink != 0
}

// The write lands on the file the link names, and the link survives.
func TestB1_ALeafSymlinkIsWrittenThroughRatherThanReplaced(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	dotfiles := t.TempDir()

	// What stow and chezmoi produce: the real file lives in a repository and
	// $HOME holds a link to it.
	real := filepath.Join(dotfiles, "codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(real), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("# managed by dotfiles\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok := findClient("codex")
	if !ok {
		t.Fatal("no client named codex")
	}
	path := c.Path(project, home)
	b1Link(t, real, path)

	if err := writeTo(c, path, project, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}

	if !isLink(t, path) {
		t.Error("the leaf symlink was replaced by a plain file; the dotfiles repository is no " +
			"longer what this client reads, and the next `stow -R` will undo the entry")
	}
	got, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "serve-mcp") {
		t.Errorf("the write did not reach the file the link names:\n%s", got)
	}
	if !strings.Contains(string(got), "managed by dotfiles") {
		t.Errorf("the existing content of the target was lost:\n%s", got)
	}
}

// The inversion, which is F5's own hole reached from the other side: the link
// leaves $HOME, so resolving alone said "project-local" and wrote 0644 at a
// path under $HOME. The mode is decided by the name the user gave as well as by
// where it resolves, and the stricter answer wins.
func TestB1_ALinkOutOfHomeStillGetsTheHomeMode(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	outside := t.TempDir()

	// The target has to EXIST, or this fixture does not test what it says. A
	// dangling link cannot be resolved, so resolvePath falls back to the
	// deepest ancestor that does exist — which is under $HOME — and the old
	// underHome answers "yes" for the wrong reason. Caught by running this
	// against the parent commit and reading which assertion fired.
	real := filepath.Join(outside, "config.toml")
	if err := os.WriteFile(real, []byte("# in a dotfiles repo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := findClient("codex")
	path := c.Path(project, home)
	b1Link(t, real, path)

	if !underHome(path, home) {
		t.Fatal("a path the user named under $HOME was not treated as being under it because " +
			"it resolves elsewhere — that is F5 inverted")
	}
	if err := writeTo(c, path, project, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("a config the user named under $HOME was written %04o at %s, want 0600 — "+
			"this is the file that grows an API key", got, real)
	}
	if !isLink(t, path) {
		t.Error("the link out of $HOME was replaced by a plain file")
	}
}

// The other direction must not have been traded away: F5's second round made a
// project-local .cursor that is a link INTO $HOME get 0600, and it still does.
func TestB1_BothReadingsAreKeptAndTheStricterWins(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	outside := t.TempDir()

	inHome := filepath.Join(home, "shared")
	if err := os.MkdirAll(inHome, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, ".cursor")
	b1Link(t, inHome, link)
	if !underHome(filepath.Join(link, "mcp.json"), home) {
		t.Error("a project-local path resolving into $HOME lost its home scope")
	}

	// And a path that is neither named under $HOME nor resolves there is still
	// project-local. Without this, `return true` would satisfy the two above.
	plain := filepath.Join(project, ".mcp.json")
	if underHome(plain, home) {
		t.Error("an ordinary project-local path was treated as being under $HOME")
	}
	elsewhere := filepath.Join(outside, "x.json")
	if underHome(elsewhere, home) {
		t.Error("a path outside both was treated as being under $HOME")
	}
}

// A dangling link is the state a fresh machine is in before the dotfiles
// repository is cloned, and it is exactly where `kelyfos connect` should write:
// creating the target, keeping the link.
func TestB1_ADanglingLeafLinkIsCreatedThroughRatherThanReplaced(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	dotfiles := t.TempDir()

	real := filepath.Join(dotfiles, "config.toml") // does not exist yet
	c, _ := findClient("codex")
	path := c.Path(project, home)
	b1Link(t, real, path)

	if err := writeTo(c, path, project, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	if !isLink(t, path) {
		t.Error("a dangling leaf link was replaced by a plain file")
	}
	got, err := os.ReadFile(real)
	if err != nil {
		t.Fatalf("the target the link names was not created: %v", err)
	}
	if !strings.Contains(string(got), "serve-mcp") {
		t.Errorf("the write did not reach the target:\n%s", got)
	}
}

// A relative link is followed relative to the link's own directory, not to the
// process's working directory.
func TestB1_ARelativeLeafLinkIsFollowedFromItsOwnDirectory(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	dir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real.toml")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := findClient("codex")
	path := c.Path(project, home)
	b1Link(t, "real.toml", path)

	if err := writeTo(c, path, project, home, f5Cmd()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "serve-mcp") {
		t.Errorf("a relative link was not followed from its own directory:\n%s", got)
	}
}
