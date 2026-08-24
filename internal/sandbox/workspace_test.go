package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// staged builds a Staged by hand, without mke2fs or debugfs.
//
// Commit is the part under test and it touches neither: it renames directories
// that Stage has already produced. Driving it directly is what lets these tests
// run anywhere, including the machines that have no workspace tooling at all.
func staged(t *testing.T, contents map[string]string) *Staged {
	t.Helper()
	root := t.TempDir()
	host := filepath.Join(root, "work")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range contents {
		if err := os.WriteFile(filepath.Join(host, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fp, err := Fingerprint(host)
	if err != nil {
		t.Fatal(err)
	}
	w := &Workspace{HostDir: host, ImagePath: filepath.Join(root, "ws.ext4"), fingerprint: fp}

	// What Stage would have extracted: the tree as the sandbox left it.
	tree := host + ".kelyfos-sync"
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "from-the-sandbox"), []byte("agent wrote this"), 0o644); err != nil {
		t.Fatal(err)
	}
	return &Staged{w: w, tree: tree, dest: host}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// M-3. The window between the review being shown and the answer arriving is
// however long a person takes to read it, and everything they edit in that
// window used to be destroyed by the commit that followed.
//
// Stage fingerprints, the summary prints, a human reads it — and the old Commit
// renamed the host directory away without looking again. This is the default
// flow: `kelyfos run --workspace . --review`.
func TestAnEditMadeWhileTheReviewWasOpenIsNotDestroyed(t *testing.T) {
	s := staged(t, map[string]string{"notes.md": "before"})
	host := s.w.HostDir

	// The person reads the review, then edits a file in their editor.
	if err := os.WriteFile(filepath.Join(host, "notes.md"), []byte("edited while reviewing"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest, diverted, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if !diverted {
		t.Error("the commit overwrote a directory that changed while the review was open")
	}
	if dest == host {
		t.Errorf("the sandbox's tree was written over the host directory: %s", dest)
	}
	if got := read(t, filepath.Join(host, "notes.md")); got != "edited while reviewing" {
		t.Errorf("the edit was destroyed: notes.md is %q", got)
	}
	if got := read(t, filepath.Join(dest, "from-the-sandbox")); got != "agent wrote this" {
		t.Errorf("the sandbox's work was lost as well: %q", got)
	}
}

// The ordinary case still writes back over the directory. A guard that diverts
// when nothing changed would make the feature useless in the name of safety.
func TestAnUntouchedDirectoryIsStillWrittenBackOverItself(t *testing.T) {
	s := staged(t, map[string]string{"notes.md": "before"})
	host := s.w.HostDir

	dest, diverted, err := s.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if diverted {
		t.Errorf("an untouched directory was diverted to %s", dest)
	}
	if dest != host {
		t.Errorf("dest = %s, want the host directory", dest)
	}
	if got := read(t, filepath.Join(host, "from-the-sandbox")); got != "agent wrote this" {
		t.Errorf("the sandbox's work did not land: %q", got)
	}
	if _, err := os.Stat(filepath.Join(host, "notes.md")); err == nil {
		t.Error("a file the sandbox deleted was resurrected by the swap")
	}
}

// The previous copy survives the run that replaced it. It used to be deleted
// one statement after the swap that made it worth having — which is to say, at
// the exact moment somebody would want it.
func TestThePreviousCopyIsKeptAfterASuccessfulRun(t *testing.T) {
	s := staged(t, map[string]string{"notes.md": "the version being replaced"})
	host := s.w.HostDir

	if _, _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	prev := host + ".kelyfos-previous"
	if _, err := os.Stat(prev); err != nil {
		t.Fatalf("no %s after a successful run: %v", filepath.Base(prev), err)
	}
	if got := read(t, filepath.Join(prev, "notes.md")); got != "the version being replaced" {
		t.Errorf("the previous copy is not what was replaced: %q", got)
	}

	// And the next successful run clears it, so this is one generation deep
	// rather than an accumulating pile of directories nobody asked for.
	s2 := staged(t, map[string]string{"notes.md": "second run"})
	s2.w.HostDir, s2.dest = host, host
	if fp, err := Fingerprint(host); err == nil {
		s2.w.fingerprint = fp
	}
	_ = os.RemoveAll(s2.tree)
	s2.tree = host + ".kelyfos-sync"
	if err := os.MkdirAll(s2.tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s2.tree, "second"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s2.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(prev, "second")); err == nil {
		t.Error("the second run's previous copy is the second run's own tree")
	}
	if _, err := os.Stat(prev); err != nil {
		t.Errorf("the second run left no previous copy: %v", err)
	}
}

// A declined review diverts on purpose, and the late-edit check must not undo
// that by deciding the directory looks fine after all.
func TestAnExplicitDiversionIsNotSecondGuessed(t *testing.T) {
	s := staged(t, map[string]string{"notes.md": "before"})
	host := s.w.HostDir

	where, err := s.Divert()
	if err != nil {
		t.Fatal(err)
	}
	if where != host+".kelyfos-out" {
		t.Errorf("a declined review wrote to %s", where)
	}
	if got := read(t, filepath.Join(host, "notes.md")); got != "before" {
		t.Errorf("a declined review touched the host directory: %q", got)
	}
}
