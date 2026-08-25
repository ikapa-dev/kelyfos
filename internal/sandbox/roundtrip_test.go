package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The other half of P6-24, and the half a boundary fix most easily loses.
//
// Validating an image and refusing what it cannot use is worth nothing if the
// images people actually have are among the refused. This is a project of the
// ordinary kind — nested directories, a dotfile directory, a name with spaces,
// a name that is not ASCII, a script that has to stay executable, and symlinks
// of both shapes — and every part of it has to come back.
func TestRoundTripKeepsARealProject(t *testing.T) {
	needsImageTools(t)
	root := t.TempDir()
	src := filepath.Join(root, "proj")
	for _, d := range []string{"src", "sub/deep", ".git"} {
		if err := os.MkdirAll(filepath.Join(src, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]os.FileMode{
		"README.md": 0o644, "src/main.go": 0o644,
		"build.sh": 0o755, "sub/deep/note.txt": 0o600,
		".git/config": 0o644, "a file with spaces.txt": 0o644,
		"umask-002-style.txt": 0o664,
		"unicode-ρυθμός.txt":  0o644,
	}
	for name, mode := range files {
		p := filepath.Join(src, name)
		if err := os.WriteFile(p, []byte("content of "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("src/main.go", filepath.Join(src, "link-to-main")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../deep/note.txt", filepath.Join(src, "sub", "rel-link")); err != nil {
		t.Fatal(err)
	}

	img := filepath.Join(root, "ws.ext4")
	out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F", "-d", src, img, "8192k").CombinedOutput()
	if err != nil {
		t.Fatalf("mke2fs: %v %s", err, out)
	}

	dest := filepath.Join(root, "back")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := listImage(img)
	if err != nil {
		t.Fatalf("a legitimate project was refused: %v", err)
	}
	r, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := extractImage(img, entries, r); err != nil {
		t.Fatalf("extract: %v", err)
	}

	for name, mode := range files {
		p := filepath.Join(dest, name)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s did not come back: %v", name, err)
			continue
		}
		if string(b) != "content of "+name+"\n" {
			t.Errorf("%s came back as %q", name, b)
		}
		// The exact mode, not merely a safe one. The regression this guards
		// against changed every 0664 file in a project to 0644, so `--review`
		// reported files nothing had touched as modified — caught by the
		// acceptance suite, and it belongs here where it is cheap to notice.
		info, _ := os.Lstat(p)
		if got := info.Mode().Perm(); got != mode {
			t.Errorf("%s came back %v, want the mode it went in with, %v", name, got, mode)
		}
	}
	for link, want := range map[string]string{"link-to-main": "src/main.go", "sub/rel-link": "../deep/note.txt"} {
		got, err := os.Readlink(filepath.Join(dest, link))
		if err != nil {
			t.Errorf("symlink %s did not come back: %v", link, err)
			continue
		}
		if got != want {
			t.Errorf("symlink %s -> %q, want %q", link, got, want)
		}
	}
	t.Logf("%d entries round-tripped", len(entries))
}
