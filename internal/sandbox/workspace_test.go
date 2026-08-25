package sandbox

import (
	"fmt"
	"io/fs"
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

// clearable hands a temporary tree back in a state t.TempDir can delete.
//
// A directory without owner-write is exactly what os.RemoveAll cannot empty,
// and the tests below build them on purpose, so the harness's own cleanup would
// fail the test for a reason that has nothing to do with what it asserts.
func clearable(t *testing.T, root string) {
	t.Helper()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
	})
}

// readOnlyVendor is the ordinary thing a project has that this is about: a
// vendored tree somebody checked in without owner-write.
func readOnlyVendor(t *testing.T, dir string) {
	t.Helper()
	vendor := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendor, "dep.go"), []byte("package dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vendor, 0o555); err != nil {
		t.Fatal(err)
	}
}

// A project with a read-only directory in it can be synced back more than once.
//
// Every commit clears `<dir>.kelyfos-previous` before renaming the directory it
// is replacing into that name, and os.RemoveAll cannot empty a directory that
// lacks owner-write — unlinking a child needs write on the parent. The clear
// failed silently, and one line later the rename found a non-empty directory in
// its way and returned an error, so the *second* run over such a project failed
// outright and the person was told nothing about why.
//
// This was reachable before the extraction stopped forcing u+rwx on directories
// — the previous copy is the host's own tree, with the host's own modes — and
// it is reachable every run now that a read-only directory comes back read-only,
// which is why the removal had to learn to unlock what it is deleting.
func TestASecondRunOverAProjectWithAReadOnlyDirectoryStillCommits(t *testing.T) {
	root := t.TempDir()
	clearable(t, root)
	host := filepath.Join(root, "work")
	if err := os.MkdirAll(host, 0o755); err != nil {
		t.Fatal(err)
	}
	readOnlyVendor(t, host)

	run := func(n int) {
		t.Helper()
		fp, err := Fingerprint(host)
		if err != nil {
			t.Fatal(err)
		}
		w := &Workspace{HostDir: host, ImagePath: filepath.Join(root, "ws.ext4"), fingerprint: fp}
		tree := host + ".kelyfos-sync"
		if err := os.MkdirAll(tree, 0o755); err != nil {
			t.Fatal(err)
		}
		// The extraction hands the directory back the way it was packed.
		readOnlyVendor(t, tree)
		if err := os.WriteFile(filepath.Join(tree, "written.txt"), []byte(fmt.Sprint(n)), 0o644); err != nil {
			t.Fatal(err)
		}
		s := &Staged{w: w, tree: tree, dest: host}
		dest, diverted, err := s.Commit()
		if err != nil {
			t.Fatalf("run %d could not be synced back: %v", n, err)
		}
		if diverted {
			t.Fatalf("run %d was diverted to %s, and nothing had changed", n, dest)
		}
	}
	run(1)
	run(2)

	if got := read(t, filepath.Join(host, "written.txt")); got != "2" {
		t.Errorf("the second run's work is not in place: %q", got)
	}
	if got := read(t, filepath.Join(host, "vendor", "dep.go")); got != "package dep\n" {
		t.Errorf("the read-only directory did not survive the swap: %q", got)
	}
}

// Discarding an extraction that carries a read-only directory has to actually
// remove it. A `<dir>.kelyfos-sync` left behind is not litter: Stage clears that
// name and then extracts into it, so a tree it could not clear is one the next
// run inherits files from.
func TestADiscardedExtractionWithAReadOnlyDirectoryIsReallyGone(t *testing.T) {
	root := t.TempDir()
	clearable(t, root)
	host := filepath.Join(root, "work")
	tree := host + ".kelyfos-sync"
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	readOnlyVendor(t, tree)

	s := &Staged{w: &Workspace{HostDir: host}, tree: tree, dest: host}
	s.Discard()
	if _, err := os.Stat(tree); err == nil {
		t.Error("a discarded extraction is still on disk, and the next run will extract into it")
	}
}

// unremovable builds a directory the removal cannot finish with, and hands back
// its path.
//
// The real case is a subtree the invoking user cannot unlink — a root-owned
// node_modules a container left behind — which a test cannot create. What it can
// create is the same refusal from the other side: a parent without write, so the
// tree inside it is emptied and then cannot be unlinked from its own parent. The
// removal fails at the last step either way, and what is being asserted is the
// state it leaves behind when it does.
func unremovable(t *testing.T, perm os.FileMode) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root is refused nothing, so there is no removal here that can fail")
	}
	root := t.TempDir()
	clearable(t, root)
	outer := filepath.Join(root, "outer")
	backup := filepath.Join(outer, "work.kelyfos-previous")
	if err := os.MkdirAll(backup, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "notes.md"), []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The backup's own mode goes on after it has been filled, and the parent's
	// last of all, because each one stops the writes above it.
	if err := os.Chmod(backup, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outer, 0o555); err != nil {
		t.Fatal(err)
	}
	return backup
}

// A removal that cannot finish leaves the modes of the directories that never
// refused it alone.
//
// `<dir>.kelyfos-previous` is not one of this package's scratch trees: Commit
// renames the person's own project there and leaves it as the recoverable copy
// of what a run replaced. The retry used to walk it and chmod every directory in
// it to 0700, which is how a 0750 backup — group-readable, the way a shared
// checkout is — came back with the group bits gone. It had refused nothing: a
// directory with u+rwx cannot be what denied an unlink.
func TestARemovalThatCannotFinishLeavesTheBackupsOwnModeAlone(t *testing.T) {
	backup := unremovable(t, 0o750)

	if err := removeTree(backup); err == nil {
		t.Fatal("the removal was expected to fail; the assertion below is about what it leaves behind")
	}
	info, err := os.Lstat(backup)
	if err != nil {
		t.Fatalf("the backup is gone, and this test is about the one that stays: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Errorf("the backup was left at %04o; it went in at 0750 and never refused anything", got)
	}
}

// And a directory that did refuse gets its mode back if it is still there.
//
// This is the one the retry legitimately has to open up — 0500 is exactly what
// os.RemoveAll cannot empty — so it is unlocked, emptied, and then the removal
// fails at the step above for a reason no chmod here can answer. What must not
// happen is that the person is left holding a directory this widened.
func TestADirectoryUnlockedForARemovalThatFailsGetsItsModeBack(t *testing.T) {
	backup := unremovable(t, 0o500)

	if err := removeTree(backup); err == nil {
		t.Fatal("the removal was expected to fail; the assertion below is about what it leaves behind")
	}
	info, err := os.Lstat(backup)
	if err != nil {
		t.Fatalf("the backup is gone, and this test is about the one that stays: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o500 {
		t.Errorf("the backup was left at %04o, not the 0500 it went in at", got)
	}
	// The unlocking still has to have happened, or this is passing by not
	// trying: what it was for was emptying the directory.
	if _, err := os.Stat(filepath.Join(backup, "notes.md")); err == nil {
		t.Error("nothing inside the directory was removed, so it was never unlocked at all")
	}
}

// The backup tree keeps its setgid bit through a removal that has to unlock it
// (P6-28).
//
// removeUnlocking is pointed at `<dir>.kelyfos-previous`, which is the person's
// own previous project directory kept as a recoverable backup. A shared-group
// checkout keeps its directories setgid deliberately, and restoring Perm() alone
// after unlocking clears that — silently, because diff.go's scanTree records
// only Mode().Perm(), so nothing in the product would ever report it. The person
// finds out when new files start landing in the wrong group.
func TestARemovalThatUnlocksADirectoryPutsItsSetgidBack(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "keepme")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Populated first: the point is a directory whose own mode refuses, and it
	// cannot be filled once it does.
	child := filepath.Join(dir, "sub")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// setgid on a directory does not stick on every filesystem; if it will not
	// hold here there is nothing to assert.
	if err := os.Chmod(dir, 0o500|os.ModeSetgid); err != nil {
		t.Skipf("cannot set setgid here: %v", err)
	}
	if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSetgid == 0 {
		t.Skip("this filesystem does not keep a setgid directory's bit")
	}
	// The parent refuses the unlink, so `dir` is unlocked and emptied and then
	// survives — which is the only path on which the mode is put back, and
	// therefore the only path where losing setgid is observable.
	if err := os.Chmod(root, 0o500); err != nil {
		t.Skipf("cannot make the parent unwritable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	_ = removeUnlocking(dir)

	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("the directory was removed, so the restore path this test exists "+
			"to check never ran: %v", err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Errorf("the backup directory lost its setgid bit: %v.\n"+
			"Restoring Mode().Perm() clears setuid, setgid and sticky, and nothing "+
			"in the product reports it because scanTree only records Perm().", info.Mode())
	}
}
