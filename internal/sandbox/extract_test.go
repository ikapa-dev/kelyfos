package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// handBack puts owner-write back on a directory once the test is over.
//
// t.TempDir deletes what it handed out and fails the test if it cannot, and a
// read-only directory is precisely what it cannot delete: unlinking a child
// needs write on the parent. These fixtures are read-only on purpose, so the
// test has to hand them back in a state the harness can clear.
func handBack(t *testing.T, dirs ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, d := range dirs {
			_ = os.Chmod(d, 0o755)
		}
	})
}

// A read-only file the sandbox never opened comes back read-only.
//
// The extraction has to be able to write what it is unpacking — a file has to
// be written and a directory has to be written into — so it forces the owner
// bits on while it works. What it used to do was leave them on. A project with
// a 0444 file in it (something generated and deliberately made unwritable, a
// vendored tree checked in at 0555) came back with every one of those entries
// rewritten: the comparison in diff.go reported `mode 0444 → 0644` for a file
// nothing had touched, and the sync-back renamed that tree over the person's
// directory, so the permission changed on their own disk.
//
// That is the group-write defect one bit over, and the same sentence answers
// it: a boundary that rewrites the user's files to protect them from the user
// is not protecting anybody.
func TestAnUntouchedReadOnlyEntryComesBackWithTheModeItWasPackedWith(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	src := filepath.Join(root, "proj")
	vendor := filepath.Join(src, "vendor")
	if err := os.MkdirAll(vendor, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "generated.go"), []byte("// do not edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendor, "dep.go"), []byte("package dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(src, "generated.go"), 0o444); err != nil {
		t.Fatal(err)
	}
	// The directory goes read-only last, because everything inside it had to be
	// written first.
	if err := os.Chmod(vendor, 0o555); err != nil {
		t.Fatal(err)
	}
	handBack(t, vendor)

	// What the manifest recorded when this was packed. Note that recording it
	// at all is proof of the floor safeMode is allowed to keep: the walk read
	// every file and entered every directory, so an entry that came from the
	// host had u+r, or u+rx, before it was packed or it could not have been.
	packed, err := scanTree(src)
	if err != nil {
		t.Fatal(err)
	}

	img := filepath.Join(root, "ws.ext4")
	if out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", src, img, "8192k").CombinedOutput(); err != nil {
		t.Fatalf("mke2fs: %v %s", err, out)
	}

	dest := filepath.Join(root, "back")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	handBack(t, filepath.Join(dest, "vendor"))
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

	for name, want := range map[string]os.FileMode{
		"generated.go":  0o444,
		"vendor":        0o555,
		"vendor/dep.go": 0o644,
		"main.go":       0o644,
	} {
		info, err := os.Lstat(filepath.Join(dest, name))
		if err != nil {
			t.Errorf("%s did not come back: %v", name, err)
			continue
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s came back %v, want the mode it went in with, %v", name, got, want)
		}
	}
	// The read-only directory still had to be written into on the way through.
	if b, err := os.ReadFile(filepath.Join(dest, "vendor", "dep.go")); err != nil {
		t.Errorf("the contents of a read-only directory were not extracted: %v", err)
	} else if string(b) != "package dep\n" {
		t.Errorf("vendor/dep.go came back as %q", b)
	}

	// And the whole point of the mode surviving: the comparison a person is
	// shown must not name a file the sandbox never opened.
	m := &WorkspaceManifest{Schema: manifestSchema, Root: src, Entries: packed}
	oldRoot = src
	defer func() { oldRoot = "" }()
	changes, err := CompareTree(m, dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("a run that changed nothing reported changes:\n%s", FormatChanges(changes))
	}
}

// The floor that survives is the one the host needs to read back what it wrote,
// and nothing more.
//
// It is stated as a table because the interesting part is which modes are left
// exactly alone: every one of them is a mode a person can have packed, and the
// only entries the floor ever reaches are the ones a guest invented.
func TestOnlyTheBitsTheHostNeedsAreForcedOntoAnExtractedMode(t *testing.T) {
	for _, c := range []struct {
		in   os.FileMode
		dir  bool
		want os.FileMode
		why  string
	}{
		{0o444, false, 0o444, "a file the person made read-only stays read-only"},
		{0o555, true, 0o555, "a vendored tree checked in read-only stays read-only"},
		{0o664, false, 0o664, "group-write is the umask-002 case and is left alone"},
		{0o755, true, 0o755, "an ordinary directory is untouched"},
		{0o777, false, 0o775, "world-write is the one permission that goes"},
		{0o666, false, 0o664, "world-write goes without disturbing the rest"},
		{os.ModeSetuid | 0o755, false, 0o755, "setuid does not survive Perm()"},
		{os.ModeSticky | 0o777, true, 0o775, "nor does the sticky bit"},
		{0o000, false, 0o400, "a mode only a guest can have written is floored so the diff can read it"},
		{0o000, true, 0o500, "and a directory so the diff can walk it"},
	} {
		if got := safeMode(c.in, c.dir); got != c.want {
			t.Errorf("safeMode(%04o, dir=%v) = %04o, want %04o — %s", c.in.Perm(), c.dir, got, c.want, c.why)
		}
	}

	// And while the extraction is still running the host keeps what it needs to
	// finish writing, which is the whole reason the forcing existed.
	if got := extractMode(0o444, false); got&0o600 != 0o600 {
		t.Errorf("extractMode(0444) = %04o; the copy cannot write a file it cannot open for writing", got)
	}
	if got := extractMode(0o555, true); got&0o700 != 0o700 {
		t.Errorf("extractMode(0555, dir) = %04o; nothing can be created inside it", got)
	}
	if got := extractMode(0o777, false); got&0o002 != 0 {
		t.Errorf("extractMode(0777) = %04o; world-write must not exist even for the length of a copy", got)
	}
}

// A setgid the host's own filesystem put on a directory survives the extraction.
//
// The standard way a team keeps a checkout group-owned is chmod g+s on the
// directory above it: the kernel then gives every directory created underneath
// the same bit, and every file underneath the parent's group. The extraction
// tree is created under that parent, so it inherits the bit and Commit renames
// it into the project's place.
//
// The chmod that puts a directory's packed mode back is what took it away.
// chmod(2) sets the whole mode word, and the mode it was handed came from
// Perm(), so S_ISGID went with it — every directory in the tree, every run.
// Nothing reported it, either: scanTree records Mode().Perm(), so CompareTree
// cannot see the difference, and what the person eventually notices is new
// files landing in the wrong group.
//
// What is put back is the bit the *host* set. The guest's own is still dropped
// — that is docs/threat-model.md's rule about guest-chosen modes and it has not
// moved — and the two cases below are here together so the difference is one
// thing to read rather than two.
func TestASetgidTheHostSetSurvivesButOneTheGuestAskedForDoesNot(t *testing.T) {
	tree := t.TempDir()

	// In the real case the kernel puts this bit here, by inheritance from a
	// parent that has it. macOS does not inherit it, so it is set directly:
	// what is under test is the chmod that follows, not who set it first.
	shared := filepath.Join(tree, "shared")
	if err := os.Mkdir(shared, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o770|os.ModeSetgid); err != nil {
		t.Skipf("this filesystem will not hold a setgid directory: %v", err)
	}
	if info, err := os.Lstat(shared); err != nil || info.Mode()&os.ModeSetgid == 0 {
		t.Skip("this filesystem does not keep a setgid directory's bit")
	}

	r, err := os.OpenRoot(tree)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	// Directory entries only, so this needs no image tools: dumpFiles has
	// nothing to dump and returns before it would run debugfs. `shared` already
	// exists, which is the state the inheriting mkdir leaves behind and which
	// extractImage tolerates.
	//
	// The other two are what a guest asking for setgid looks like on the way
	// out of an image: entryFrom keeps the raw low bits, and a caller that
	// built the flag directly would be no better off.
	entries := []imageEntry{
		{path: "shared", mode: 0o770, kind: kindDir},
		{path: "raw", mode: os.FileMode(0o2755), kind: kindDir},
		{path: "flagged", mode: os.ModeSetgid | 0o755, kind: kindDir},
	}
	if err := extractImage("", entries, r); err != nil {
		t.Fatalf("extract: %v", err)
	}

	info, err := os.Lstat(shared)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Errorf("the setgid the host set was stripped (%v); a shared-group checkout comes back "+
			"regrouped and no comparison says so", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o770 {
		t.Errorf("shared came back %04o, want the mode it was packed with, 0770", got)
	}
	for _, name := range []string{"raw", "flagged"} {
		info, err := os.Lstat(filepath.Join(tree, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Errorf("%s came back %v; a bit the guest chose reached the host's filesystem", name, info.Mode())
		}
		if got := info.Mode().Perm(); got != 0o755 {
			t.Errorf("%s came back %04o, want 0755", name, got)
		}
	}
}
