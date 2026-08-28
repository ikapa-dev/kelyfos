package sandbox

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// F17. A file the image could not give back is written over the user's own copy
// of it, empty, and the sync-back reports success.
//
// "Nothing staged" was the whole per-file check, and it is the wrong test.
// `debugfs dump` opens its destination with O_CREAT|O_TRUNC and then copies
// block by block; a failure part way through — a read error, or ENOSPC on the
// staging filesystem — leaves a file that *exists* and is short. copyThrough
// finds it, installs it, and Commit renames the tree over the project. The only
// other copy of the person's work at that moment is `.kelyfos-previous`.
//
// Reproduced rather than argued, against the real tool. The image is built from
// the project and then cut short, so every data block of big.txt is unreadable
// while the inode that names it — and the size it records — still reads
// perfectly:
//
//	debugfs -f script ws.ext4     exit 0
//	  stdout: debugfs: dump -p "/big.txt" …/0
//	  stderr: dump: Attempt to read block from filesystem resulted in short read
//	  …/0 is 0 bytes
//
// Exit 0 is what makes it silent: dumpFiles only looked at the process's own
// status, and debugfs reports a per-command failure through com_err and carries
// on. The record already carries the answer — `ls -l -p` prints the inode's
// size — so the extraction can tell that what came out is not what was in there.
func TestF17_APartiallyDumpedFileIsNotCommittedOverTheProject(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	proj := filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("A"), 1<<20)
	if err := os.WriteFile(filepath.Join(proj, "big.txt"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	img := filepath.Join(root, "ws.ext4")
	if out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", proj, img, "8192k").CombinedOutput(); err != nil {
		t.Fatalf("mke2fs: %v %s", err, out)
	}
	// The damage. Metadata — the superblock, the group descriptors, the inode
	// table and the root directory's own block — lives at the front of an ext4
	// image and survives this; the file's data blocks do not.
	if err := os.Truncate(img, 2000<<10); err != nil {
		t.Fatal(err)
	}

	entries, err := listImage(img)
	if err != nil {
		t.Fatalf("the damaged image was refused at enumeration, so this test never reaches "+
			"the dump it is about: %v", err)
	}
	var named bool
	for _, e := range entries {
		if e.path == "big.txt" {
			named = true
		}
	}
	if !named {
		t.Fatalf("enumeration did not find big.txt in the damaged image (%+v); the fixture is wrong", entries)
	}

	ws := &Workspace{HostDir: proj, ImagePath: img}
	if ws.fingerprint, err = Fingerprint(proj); err != nil {
		t.Fatal(err)
	}
	dest, diverted, err := ws.SyncBack()

	if err == nil {
		// It went through. What is on the person's disk now?
		info, statErr := os.Stat(filepath.Join(proj, "big.txt"))
		if statErr != nil {
			t.Fatalf("the sync-back reported success (dest %s, diverted %v) and big.txt is gone: %v",
				dest, diverted, statErr)
		}
		t.Fatalf("the sync-back reported success (dest %s, diverted %v) and replaced a %d byte file "+
			"with a %d byte one; a file the image could not give back must refuse the whole "+
			"extraction, not be committed over the only copy of it",
			dest, diverted, len(want), info.Size())
	}

	// Refused — and a refusal is only worth anything if it changed nothing.
	if !errors.Is(err, ErrHostileImage) {
		t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
	}
	got, readErr := os.ReadFile(filepath.Join(proj, "big.txt"))
	if readErr != nil {
		t.Fatalf("the refusal did not leave the project alone: %v", readErr)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("big.txt is %d bytes after the refusal, want the %d it had", len(got), len(want))
	}
	if _, err := os.Stat(proj + ".kelyfos-previous"); err == nil {
		t.Error("a refused extraction rotated the person's project away anyway")
	}
	// And nothing half-extracted left beside it.
	beside, _ := filepath.Glob(proj + ".kelyfos-sync-*")
	if len(beside) != 0 {
		t.Errorf("a refused extraction left its staging tree behind: %v", beside)
	}
}

// F17, the other half: where the dump lands, and whether that path can be
// spelled at all.
//
// Two things were wrong and they are one line apart. The staging directory came
// from os.MkdirTemp("", …) — on most Linux hosts a tmpfs, which is RAM, and the
// guest decides how many bytes the host is asked to stage — and the destination
// was interpolated into the debugfs command line unquoted, where debugfs splits
// on whitespace:
//
//	debugfs: dump -p "/c.txt" /tmp/dir with space/oc
//	dump: Usage: dump_inode [-p] <file> <output_file>
//
// So a TMPDIR containing a space broke every dump in every image. This asserts
// both at once: the extraction goes through with a space in the path, and the
// staging happened under Root() — the disk the person chose for this tool — and
// not in the system temp directory.
func TestF17_TheDumpStagesUnderRootAndSurvivesASpaceInThePath(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	t.Setenv("TMPDIR", mkdirT(t, filepath.Join(root, "temp dir")))
	t.Setenv("KELYFOS_CACHE", mkdirT(t, filepath.Join(root, "cache dir")))

	src := mkdirT(t, filepath.Join(root, "proj"))
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.ext4")
	if out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", src, img, "8192k").CombinedOutput(); err != nil {
		t.Fatalf("mke2fs: %v %s", err, out)
	}

	entries, err := listImage(img)
	if err != nil {
		t.Fatal(err)
	}
	dest := mkdirT(t, filepath.Join(root, "back"))
	r, err := os.OpenRoot(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := extractImage(img, entries, r); err != nil {
		t.Fatalf("a space in the staging path broke the extraction: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "a.txt")); err != nil || string(b) != "hello\n" {
		t.Errorf("a.txt came back as %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(Root(), "extract")); err != nil {
		t.Errorf("the dump did not stage under Root(): %v — on most Linux hosts the system temp "+
			"directory is a tmpfs, and the guest chooses how many bytes it asks the host to stage", err)
	}
}

func mkdirT(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// packImage builds an ext4 image from a directory, the way a guest hands one
// back.
func packImage(t *testing.T, src, img string) {
	t.Helper()
	if out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", src, img, "8192k").CombinedOutput(); err != nil {
		t.Fatalf("mke2fs: %v %s", err, out)
	}
}

// extractInto runs the real enumeration and extraction into a fresh tree and
// hands back whichever of the two refused, if either did.
func extractInto(t *testing.T, img, tree string) error {
	t.Helper()
	entries, err := listImage(img)
	if err != nil {
		return err
	}
	r, err := os.OpenRoot(tree)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	return extractImage(img, entries, r)
}

// F18. A chain of symlinks walks out of the workspace past a check that judges
// each link on its own.
//
// validLink asked one question per link, lexically, as though every other name
// in the tree were a real directory: does path.Join(dir(from), target) begin
// with ".."? Three links, none of which does, compose into one that leaves:
//
//	sub/d1   -> ..                joins to "."         accepted
//	sub/d2   -> d1/..             joins to "sub"       accepted
//	sub/leak -> d2/secret.txt     joins to "sub/d2/…"  accepted
//
// and really: sub/d1 is the tree, so sub/d1/.. is the tree's parent, so
// sub/leak is <parent>/secret.txt. The extraction itself cannot write through
// it — os.Root refuses a link that escapes — but the link is left in the
// person's directory for the next thing that follows it: an editor, `tar -h`,
// `rsync -L`, or `kelyfos diff`'s own os.ReadFile on an added entry. That is
// what this reads with.
//
// The fix resolves a target through the entry set instead of guessing at it,
// so a link is judged by where it actually lands. The subtests below are the
// two halves of that: what must be refused, and what must not be.
func TestF18_ASymlinkChainCannotBeLeftInTheProject(t *testing.T) {
	needsImageTools(t)

	t.Run("chain-climbs-out", func(t *testing.T) {
		root := t.TempDir()
		const secret = "a host file the guest was never given\n"
		if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		src := mkdirT(t, filepath.Join(root, "src", "sub"))
		for _, l := range []struct{ target, name string }{
			{"..", "d1"},
			{"d1/..", "d2"},
			{"d2/secret.txt", "leak"},
		} {
			if err := os.Symlink(l.target, filepath.Join(src, l.name)); err != nil {
				t.Fatal(err)
			}
		}
		img := filepath.Join(root, "ws.ext4")
		packImage(t, filepath.Join(root, "src"), img)

		// The tree's parent is `root`, which is where secret.txt is.
		tree := mkdirT(t, filepath.Join(root, "tree"))
		err := extractInto(t, img, tree)
		if err == nil {
			got, readErr := os.ReadFile(filepath.Join(tree, "sub", "leak"))
			if readErr == nil {
				t.Fatalf("the extraction accepted the chain and sub/leak reads %q — a link the "+
					"guest planted, left in the person's project, pointing at a file outside it", got)
			}
			t.Fatalf("the extraction accepted the chain (following it gave %v); each link passes the "+
				"lexical check and together they leave the workspace", readErr)
		}
		if !errors.Is(err, ErrHostileImage) {
			t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
		}
		// sub/d2 rather than sub/leak: d2 is the link that actually steps above
		// the tree, and naming the first one that does is what tells somebody
		// which entry to go and look at.
		if !strings.Contains(err.Error(), "sub/d2") {
			t.Errorf("the refusal does not name the link that climbs: %v", err)
		}
	})

	// A link that climbs and stays inside is ordinary, and refusing it would
	// cost more than the defect does. `node_modules/<pkg> -> ../../packages/x`
	// is what every pnpm and npm workspace looks like, and a refusal here
	// refuses the *whole image* — which on the resume path is the person's
	// session, since the workspace image is removed either way.
	t.Run("legitimate-climb-inside", func(t *testing.T) {
		root := t.TempDir()
		src := filepath.Join(root, "src")
		mkdirT(t, filepath.Join(src, "packages", "core"))
		mkdirT(t, filepath.Join(src, "app", "node_modules"))
		if err := os.WriteFile(filepath.Join(src, "packages", "core", "index.js"),
			[]byte("module.exports = 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../packages/core",
			filepath.Join(src, "app", "node_modules", "core")); err != nil {
			t.Fatal(err)
		}
		img := filepath.Join(root, "ws.ext4")
		packImage(t, src, img)

		tree := mkdirT(t, filepath.Join(root, "tree"))
		if err := extractInto(t, img, tree); err != nil {
			t.Fatalf("an ordinary workspace symlink was refused, and a refusal costs the person "+
				"the whole image: %v", err)
		}
		b, err := os.ReadFile(filepath.Join(tree, "app", "node_modules", "core", "index.js"))
		if err != nil || string(b) != "module.exports = 1\n" {
			t.Errorf("the link came back unusable: %q, %v", b, err)
		}
	})

	// A cycle cannot leave the tree — it just cannot be followed, by anybody.
	// Accepted for that reason: the refusal is for leaving the workspace, and
	// inventing one for a broken-but-contained link would cost an image for
	// something every tool on the host already answers with ELOOP.
	t.Run("two-link-cycle-stays-inside", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("no\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := mkdirT(t, filepath.Join(root, "src", "sub"))
		if err := os.Symlink("c2", filepath.Join(src, "c1")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("c1", filepath.Join(src, "c2")); err != nil {
			t.Fatal(err)
		}
		img := filepath.Join(root, "ws.ext4")
		packImage(t, filepath.Join(root, "src"), img)

		tree := mkdirT(t, filepath.Join(root, "tree"))
		if err := extractInto(t, img, tree); err != nil {
			t.Fatalf("a cycle inside the workspace was refused, which costs the whole image for a "+
				"link that reaches nothing: %v", err)
		}
		if _, err := os.ReadFile(filepath.Join(tree, "sub", "c1")); err == nil {
			t.Error("the cycle resolved to something, which it must not")
		}
		if got, err := os.Readlink(filepath.Join(tree, "sub", "c1")); err != nil || got != "c2" {
			t.Errorf("sub/c1 came back as %q, %v", got, err)
		}
	})

	// What os.Root actually does, measured, because two comments and the threat
	// model all said it was `openat2` with `RESOLVE_BENEATH` and
	// `RESOLVE_NO_SYMLINKS` and it is neither. Go 1.27 never calls openat2 —
	// `openat2Trap` is a syscall number in the tree that nothing uses — and
	// os.Root walks a path one component at a time with
	// openat(O_NOFOLLOW|O_CLOEXEC), resolving each link itself in checkSymlink.
	//
	// The two named flags disagree about the one case that matters, and a reader
	// who took RESOLVE_NO_SYMLINKS at its word concludes that a link the guest
	// planted cannot matter. That is the reasoning this finding was missed by,
	// so the behaviour is pinned here rather than described anywhere.
	t.Run("what-os.Root-really-does-with-a-link", func(t *testing.T) {
		tree := t.TempDir()
		mkdirT(t, filepath.Join(tree, "real"))
		outside := t.TempDir()
		for _, l := range []struct{ target, name string }{
			{"real", "rel-inside"},                          // followed
			{filepath.Join(tree, "real"), "abs-inside"},     // refused anyway
			{"../" + filepath.Base(outside), "rel-outside"}, // refused
			{outside, "abs-outside"},                        // refused
		} {
			if err := os.Symlink(l.target, filepath.Join(tree, l.name)); err != nil {
				t.Fatal(err)
			}
		}
		r, err := os.OpenRoot(tree)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()

		f, err := r.OpenFile("rel-inside/f.txt", os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatalf("os.Root refused a relative link that stays inside the tree, so it does "+
				"behave like RESOLVE_NO_SYMLINKS after all: %v", err)
		}
		f.Close()
		if _, err := os.Stat(filepath.Join(tree, "real", "f.txt")); err != nil {
			t.Errorf("the write did not land through the link: %v", err)
		}
		// An absolute link is refused even when it points back inside the root,
		// which is stricter than RESOLVE_BENEATH would be — another reason not
		// to describe this by a flag name it does not use.
		for _, name := range []string{"abs-inside", "rel-outside", "abs-outside"} {
			if _, err := r.OpenFile(name+"/f.txt", os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				t.Errorf("os.Root wrote through %s", name)
			}
		}
	})
}

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
