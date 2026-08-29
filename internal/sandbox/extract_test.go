package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
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

	// The same chain, spelled in a different case. This is F18's second route
	// and it needs no hop budget at all.
	//
	// walk decides "is this component a symlink?" by looking the resolved path up
	// in the entry set, and the set was keyed by the name exactly as the image
	// spells it. `sub/D1` is not a key, so it read as an ordinary directory and
	// the chain looked like it stayed inside. On a case-insensitive filesystem
	// `sub/D1` *is* `sub/d1` and the chain leaves — and the filesystem this
	// project's own primary platform puts the project on is case-insensitive:
	// measured, the macOS home shared into the Lima VM folds case while /tmp on
	// the same machine does not.
	//
	// The refusal does not depend on where this test happens to run, because the
	// fold is unconditional. That is deliberate: over-approximating "this is a
	// symlink" makes the walk follow more and refuse more, never fewer.
	t.Run("chain-climbs-out-in-a-different-case", func(t *testing.T) {
		root := t.TempDir()
		const secret = "a host file the guest was never given\n"
		if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		src := mkdirT(t, filepath.Join(root, "src", "sub"))
		for _, l := range []struct{ target, name string }{
			{"..", "d1"},
			{"D1/../secret.txt", "leak"},
		} {
			if err := os.Symlink(l.target, filepath.Join(src, l.name)); err != nil {
				t.Fatal(err)
			}
		}
		img := filepath.Join(root, "ws.ext4")
		packImage(t, filepath.Join(root, "src"), img)

		tree := mkdirT(t, filepath.Join(root, "tree"))
		err := extractInto(t, img, tree)
		if err == nil {
			got, readErr := os.ReadFile(filepath.Join(tree, "sub", "leak"))
			if readErr == nil {
				t.Fatalf("the extraction accepted the chain and sub/leak reads %q — the entry set "+
					"was keyed by the exact spelling and the destination filesystem does not "+
					"have to agree", got)
			}
			t.Fatal("the extraction accepted a chain whose middle component differs only in case " +
				"from a symlink in the same directory")
		}
		if !errors.Is(err, ErrHostileImage) {
			t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
		}
	})

	// A chain longer than the budget is refused rather than accepted, and the
	// reason is measured rather than assumed.
	//
	// The budget used to be non-fatal on the argument that the kernel stops at 40
	// links, so a longer chain is ELOOP for everything. That is true of *kernel*
	// path resolution and false of the tools this finding is actually about,
	// which walk links themselves. On one chain pointing at a file outside the
	// tree:
	//
	//	links   cat(2)                              os.path.realpath / EvalSymlinks
	//	   30   OUTSIDE                             …/secret.txt
	//	   45   Too many levels of symbolic links   …/secret.txt
	//	   60   Too many levels of symbolic links   …/secret.txt
	//
	// So a 41-link chain out of the workspace is unreadable by `cat` and
	// perfectly readable by an IDE, by `rsync -L`, and by any Go program calling
	// filepath.EvalSymlinks.
	t.Run("a-chain-too-long-to-follow-is-refused", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("no\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		src := mkdirT(t, filepath.Join(root, "src", "sub"))
		// Every link stays inside and no single one of them is refusable on its
		// own — l0 points at an ordinary file in the same directory. What the
		// chain has is length: following the last one takes maxLinkHops+2
		// resolutions, so the walk cannot reach the end and cannot report that it
		// stays. A fixture whose first link climbs out would prove nothing here,
		// because validLink refuses that lexically before the chain is walked at
		// all.
		if err := os.WriteFile(filepath.Join(src, "target.txt"), []byte("in\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("target.txt", filepath.Join(src, "l0")); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= maxLinkHops+1; i++ {
			if err := os.Symlink(fmt.Sprintf("l%d", i-1),
				filepath.Join(src, fmt.Sprintf("l%d", i))); err != nil {
				t.Fatal(err)
			}
		}
		img := filepath.Join(root, "ws.ext4")
		packImage(t, filepath.Join(root, "src"), img)

		tree := mkdirT(t, filepath.Join(root, "tree"))
		if err := extractInto(t, img, tree); err == nil {
			t.Fatal("a chain this host cannot follow to the end was accepted; it cannot have been " +
				"shown to stay inside the workspace, and userspace resolvers follow far past the " +
				"kernel's own limit — this one stays inside, and the point is that nothing here " +
				"established that")
		} else if !errors.Is(err, ErrHostileImage) {
			t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
		}
	})

	// Two symlinks whose names differ only in case, which the folded key cannot
	// tell apart.
	//
	// One key holds one target, so a collision would silently drop one of them
	// and judge every chain through the survivor — a wrong answer in the one
	// check whose whole job is to be right about where a chain lands. They also
	// cannot both exist where this tree is going, if that filesystem folds case.
	t.Run("two-symlinks-differing-only-in-case-are-refused", func(t *testing.T) {
		root := t.TempDir()
		src := mkdirT(t, filepath.Join(root, "src", "sub"))
		if err := os.Symlink("a.txt", filepath.Join(src, "link")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("b.txt", filepath.Join(src, "LINK")); err != nil {
			t.Skipf("this filesystem will not hold both spellings: %v", err)
		}
		img := filepath.Join(root, "ws.ext4")
		packImage(t, filepath.Join(root, "src"), img)

		tree := mkdirT(t, filepath.Join(root, "tree"))
		err := extractInto(t, img, tree)
		if err == nil {
			t.Fatal("two symlinks differing only in case were accepted; one of them decides what " +
				"every chain through that name resolves to and the other is silently gone")
		}
		if !errors.Is(err, ErrHostileImage) {
			t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
		}
	})

	// A cycle exhausts the budget, so it is refused by the same one rule.
	//
	// It is genuinely contained — a cycle reaches nothing, inside the tree or
	// out — so this is the cost of having one rule instead of two, taken
	// deliberately. A link that reaches nothing is not work anybody loses.
	t.Run("two-link-cycle-is-refused", func(t *testing.T) {
		root := t.TempDir()
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
		if err := extractInto(t, img, tree); err == nil {
			t.Fatal("a symlink cycle was accepted; it exhausts the hop budget, and exhausting the " +
				"budget is a refusal")
		} else if !errors.Is(err, ErrHostileImage) {
			t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
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

		// And the bound on how many it will follow, which is os/root.go's
		// rootMaxSymlinks = 8 — far below this package's own budget of 64, so an
		// in-tree chain this package accepts can still be refused here. Not a
		// hole (nothing escapes either way) and worth pinning, because "os.Root
		// follows an in-tree link" without a number is the same kind of
		// half-true the original comment was.
		if err := os.Symlink("real", filepath.Join(tree, "n0")); err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 12; i++ {
			if err := os.Symlink(fmt.Sprintf("n%d", i-1),
				filepath.Join(tree, fmt.Sprintf("n%d", i))); err != nil {
				t.Fatal(err)
			}
		}
		deepest := 0
		for i := 0; i <= 12; i++ {
			if _, err := r.OpenFile(fmt.Sprintf("n%d/probe%d.txt", i, i),
				os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
				deepest = i
			} else {
				break
			}
		}
		if deepest >= 12 {
			t.Errorf("os.Root followed a chain of %d in-tree links; it is documented to stop at "+
				"rootMaxSymlinks", deepest+1)
		}
		t.Logf("os.Root followed %d in-tree links and refused the next", deepest+1)
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

// F4. A directory whose name carries whitespace loses everything inside it,
// silently.
//
// The review could not reproduce this — "no toolchain was available on either
// pass" — so here it is against a real image and the real debugfs, which turns
// out to have two distinct failures rather than the one predicted.
//
// listDirs batched every directory at one level into one script and attributed
// each block of records to the directory named on the echoed command line. The
// directory was not quoted, and the echo was matched with strings.TrimSpace:
//
//	a trailing space   ls -l -p /notes      -> debugfs strips it while tokenising
//	                                          "/notes: File not found by ext2_lookup"
//	                                          and TrimSpace makes the key "/notes"
//	                                          while the directory is "/notes "
//	an interior space  ls -l -p /my notes   -> two arguments
//	                                          "Usage: ls [-c] [-d] [-l] [-p] [-r] file"
//
// Both end the same way: blocks[dir] is empty, the directory is created on the
// host with none of its contents, and nothing anywhere says so. The error text
// goes to stderr, which listDirs discarded, and debugfs exits 0 either way.
//
// Note what the review's `ls:` rule would have caught: neither. com_err is not
// what prints these — one is a lookup failure prefixed with the path and the
// other is a usage line — which is why the check that actually holds is the
// structural one: debugfs echoes every command, so a directory that produced no
// block at all means the parse drifted, whatever the message was.
func TestF4_ADirectoryNameWithWhitespaceKeepsItsContents(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	src := filepath.Join(root, "src")
	// "notes " is the trailing-space case, "my notes" the interior one, and
	// "plain" is the control: if the fix broke ordinary directories this is
	// what would say so.
	want := map[string]string{
		"notes /a.txt":   "trailing\n",
		"my notes/b.txt": "interior\n",
		"plain/c.txt":    "ordinary\n",
		"deep/ x /d.txt": "both ends\n",
		"top.txt":        "root\n",
	}
	for rel, body := range want {
		p := filepath.Join(src, rel)
		mkdirT(t, filepath.Dir(p))
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	img := filepath.Join(root, "ws.ext4")
	packImage(t, src, img)

	entries, err := listImage(img)
	if err != nil {
		t.Fatalf("a workspace with spaces in its directory names was refused: %v", err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		found[e.path] = true
	}
	for rel := range want {
		if !found[filepath.ToSlash(rel)] {
			t.Errorf("%q is in the image and the enumeration did not find it — the directory is "+
				"created on the host with none of its contents and nothing says so", rel)
		}
	}

	// And through to the person's disk, which is where it matters.
	tree := mkdirT(t, filepath.Join(root, "tree"))
	if err := extractInto(t, img, tree); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(tree, rel))
		if err != nil {
			t.Errorf("%q did not come back: %v", rel, err)
			continue
		}
		if string(got) != body {
			t.Errorf("%q came back as %q, want %q", rel, got, body)
		}
	}
}

// The cross-check on its own: a directory that produced no block is an error.
//
// debugfs echoes every command it reads from a script and every directory has
// at least `.` and `..`, so an empty block cannot happen to a directory that was
// really listed. It is what catches a drift whose message nobody predicted —
// which, as the corpus above shows, is both of the ones that actually occur.
func TestF4_ADirectoryThatProducedNoRecordsIsAnError(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	src := mkdirT(t, filepath.Join(root, "src", "real"))
	if err := os.WriteFile(filepath.Join(src, "f.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.ext4")
	packImage(t, filepath.Join(root, "src"), img)

	// A directory that is not in the image at all. listDirs is only ever handed
	// names it enumerated, so this cannot arise from a real walk — it is the
	// drift the cross-check is for, staged directly.
	if _, err := listDirs(img, []string{"/real", "/not-there"}); err == nil {
		t.Error("a directory debugfs said nothing about was treated as an empty directory; " +
			"that is how a workspace loses a subtree without an error")
	}
	// The control: the real one alone still works.
	blocks, err := listDirs(img, []string{"/", "/real"})
	if err != nil {
		t.Fatalf("an ordinary listing was refused: %v", err)
	}
	if len(blocks["/real"]) == 0 {
		t.Error("/real came back with no records")
	}
}

// entryFrom is the parser every byte of a guest-written filesystem arrives
// through, and it had no fuzz target. F17 and F4 both changed it — one added the
// size field, the other the attribution the records are grouped by — so this is
// the coverage those changes owe.
//
// What it asserts is not "no error": it is that anything *accepted* is safe to
// use, which is the claim the rest of the package rests on. The strictness is
// the check here, deliberately, rather than a check bolted beside a lenient
// parser.
func FuzzEntryFrom(f *testing.F) {
	for _, seed := range []string{
		"/12/100644/501/1000/main.go/42/",
		"/16/040775/501/1000/notes //",
		"/15/120777/501/1000/link/5/",
		"/2/040755/0/0/.//",
		"/2/040755/0/0/..//",
		"/11/040700/0/0/lost+found//",
		"/12/100644/501/1000/../../pwn./21/",
		"/12/100644/501/1000/a\" b/1/",
		"/12/060644/501/1000/dev/0/",
		"/12/100644/501/1000/big/-1/",
		"/12/100644/501/1000/big/99999999999999999999/",
		"",
		"//////",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, record string) {
		for _, dir := range []string{"/", "/sub", "/a b", "/notes "} {
			e, err := entryFrom(dir, record)
			if err != nil || e == nil {
				continue
			}
			// A name that reaches here is joined to a host path through an
			// os.Root and interpolated into a double-quoted debugfs argument.
			if e.path == "" || path.IsAbs(e.path) {
				t.Fatalf("accepted %q in %q with path %q", record, dir, e.path)
			}
			for _, seg := range strings.Split(e.path, "/") {
				if seg == "" || seg == "." || seg == ".." {
					t.Fatalf("accepted %q in %q with path %q", record, dir, e.path)
				}
			}
			if strings.ContainsAny(e.path, "\x00\"'") {
				t.Fatalf("accepted %q in %q with path %q", record, dir, e.path)
			}
			for _, r := range e.path {
				if (r < 0x20 || r == 0x7f) && r != '/' {
					t.Fatalf("accepted %q in %q with a control character in %q", record, dir, e.path)
				}
			}
			// The size is what F17's check compares a dump against, so a
			// negative or unparsed one would disable that check rather than
			// trip it.
			if e.size < 0 {
				t.Fatalf("accepted %q with size %d", record, e.size)
			}
			switch e.kind {
			case kindDir:
				if e.size != 0 {
					t.Fatalf("accepted directory %q with size %d", record, e.size)
				}
			case kindFile, kindSymlink:
			default:
				t.Fatalf("accepted %q with kind %d", record, e.kind)
			}
			if e.mode&^os.FileMode(0o7777) != 0 {
				t.Fatalf("accepted %q with mode %v", record, e.mode)
			}
		}
	})
}

// F17's headline mechanism, pinned on its own.
//
// The first F17 test was satisfied by *either* the size comparison or the
// com_err rule and pinned neither: both size checks could be deleted with the
// suite green. They are not interchangeable — the comment above copyThrough
// says the size check exists so the defence is "structural rather than a matter
// of noticing a message" — and this is the case where only the size check can
// fire.
//
// A file that grows between the two debugfs passes. Enumeration and dumping are
// separate processes, so a workspace still being written to is read at two
// different moments; the dump then succeeds, says nothing on stderr, and hands
// back more bytes than the record accounted for.
func TestF17_TheSizeCheckCatchesAFileThatChangedBetweenThePasses(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	src := mkdirT(t, filepath.Join(root, "src"))
	if err := os.WriteFile(filepath.Join(src, "work.txt"), []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.ext4")
	packImage(t, src, img)

	entries, err := listImage(img)
	if err != nil {
		t.Fatal(err)
	}

	// The guest keeps working. The image at the same path now holds a longer
	// file under the same name, which is what dumpFiles will read.
	if err := os.WriteFile(filepath.Join(src, "work.txt"),
		[]byte("first\nand a good deal more that was not there a moment ago\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	packImage(t, src, img)

	tree := mkdirT(t, filepath.Join(root, "tree"))
	r, err := os.OpenRoot(tree)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	err = extractImage(img, entries, r)
	if err == nil {
		t.Fatal("a file whose contents did not match what was enumerated was written into the " +
			"tree; debugfs said nothing on stderr, so the size comparison is the only thing " +
			"that can catch this")
	}
	if !errors.Is(err, ErrHostileImage) {
		t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
	}
	// The message identifies which check fired. If this ever reads like a
	// debugfs complaint, the size comparison has stopped being what catches it.
	if !strings.Contains(err.Error(), "its record says it holds") {
		t.Errorf("this was not refused by the size comparison: %v", err)
	}
}

// The same rule for a symlink, which copyThrough never sees.
//
// The links pass is deliberately not fatal on stderr — a fast link has no data
// block, so `dump` on it legitimately writes nothing and reports a short read —
// and copyThrough only runs for kindFile. So a *slow* link whose dump came back
// short was recreated pointing at a truncated version of wherever the guest
// meant, which is somewhere else entirely.
func TestF17_ASymlinkTargetIsCheckedAgainstItsRecordedLength(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	src := mkdirT(t, filepath.Join(root, "src"))
	// 200 bytes, well past the 59 at which ext4 stops storing a target inside
	// the inode, so this one has a data block and `dump` is its only reader.
	if err := os.Symlink(strings.Repeat("a", 200), filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.ext4")
	packImage(t, src, img)

	entries, err := listImage(img)
	if err != nil {
		t.Fatal(err)
	}
	var size int64
	for _, e := range entries {
		if e.path == "link" {
			if e.kind != kindSymlink {
				t.Fatalf("link came back as kind %d", e.kind)
			}
			size = e.size
		}
	}
	if size != 200 {
		t.Fatalf("the record says the target is %d bytes, want 200 — the fixture is wrong", size)
	}

	// The image now holds a shorter target at the same name, which is what the
	// dump will read against the record above.
	if err := os.Remove(filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(strings.Repeat("a", 100), filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	packImage(t, src, img)

	tree := mkdirT(t, filepath.Join(root, "tree"))
	r, err := os.OpenRoot(tree)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := extractImage(img, entries, r); err == nil {
		got, readErr := os.Readlink(filepath.Join(tree, "link"))
		t.Fatalf("a truncated symlink target was recreated as %q (%d bytes, %v); the record says "+
			"200 and a short target points somewhere else entirely", got, len(got), readErr)
	} else if !strings.Contains(err.Error(), "its record says it holds") {
		t.Errorf("this was not refused by the length comparison: %v", err)
	}

	// And an ordinary workspace full of symlinks of both kinds still goes
	// through — the check must not cost a project its links.
	ok := mkdirT(t, filepath.Join(root, "ok"))
	if err := os.WriteFile(filepath.Join(ok, "f.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"fast":     "f.txt",
		"fast-max": strings.Repeat("b", 59),
		"slow-min": strings.Repeat("c", 60),
		"slow-big": strings.Repeat("d", 200),
		"spaces":   "a b c",
	} {
		if err := os.Symlink(target, filepath.Join(ok, name)); err != nil {
			t.Fatal(err)
		}
	}
	okImg := filepath.Join(root, "ok.ext4")
	packImage(t, ok, okImg)
	okTree := mkdirT(t, filepath.Join(root, "ok-tree"))
	if err := extractInto(t, okImg, okTree); err != nil {
		t.Fatalf("an ordinary set of symlinks was refused: %v", err)
	}
	for name, want := range map[string]string{
		"fast":     "f.txt",
		"fast-max": strings.Repeat("b", 59),
		"slow-min": strings.Repeat("c", 60),
		"slow-big": strings.Repeat("d", 200),
		"spaces":   "a b c",
	} {
		got, err := os.Readlink(filepath.Join(okTree, name))
		if err != nil || got != want {
			t.Errorf("%s came back as %q (%v), want %q", name, got, err, want)
		}
	}
}

// The com_err rule, pinned where it is used rather than only where it is
// defined.
//
// dumpFiles refuses when debugfs reports a per-command failure on stderr for a
// regular file. Every such failure this could construct is *also* a size
// mismatch, so the end-to-end tests above cannot tell the two defences apart —
// which is what let both size checks be deleted with the suite green. Handing
// dumpFiles an entry whose recorded size is what a failed dump actually
// produces separates them: the size comparison lives in copyThrough and does
// not run here, so only the stderr rule can refuse this.
func TestF17_DebugfsComErrOnAFileDumpIsFatal(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	src := mkdirT(t, filepath.Join(root, "src"))
	if err := os.WriteFile(filepath.Join(src, "big.txt"),
		bytes.Repeat([]byte("A"), 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.ext4")
	packImage(t, src, img)
	if err := os.Truncate(img, 2000<<10); err != nil {
		t.Fatal(err)
	}

	// size 0, which is exactly what the failed dump leaves staged.
	_, cleanup, err := dumpFiles(img, []imageEntry{{path: "big.txt", kind: kindFile, size: 0}})
	defer cleanup()
	if err == nil {
		t.Fatal("debugfs reported `dump: Attempt to read block from filesystem resulted in short " +
			"read` and exited 0, and dumpFiles treated that as a successful dump")
	}
	if !errors.Is(err, ErrHostileImage) {
		t.Errorf("the refusal is %v, which does not wrap ErrHostileImage", err)
	}

	// A symlink pass must NOT be fatal on the same stream, because a fast link
	// has no data block and reports that same short read every single time.
	linkSrc := mkdirT(t, filepath.Join(root, "links"))
	if err := os.WriteFile(filepath.Join(linkSrc, "f.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f.txt", filepath.Join(linkSrc, "s")); err != nil {
		t.Fatal(err)
	}
	linkImg := filepath.Join(root, "links.ext4")
	packImage(t, linkSrc, linkImg)
	_, cleanup2, err := dumpFiles(linkImg, []imageEntry{{path: "s", kind: kindSymlink, size: 5}})
	defer cleanup2()
	if err != nil {
		t.Errorf("a fast symlink made the dump fatal, which would refuse most real workspaces: %v", err)
	}
}

// debugfsErrors on its own: what counts as the tool reporting a failure.
func TestF17_DebugfsErrorsPicksOutComErrLinesOnly(t *testing.T) {
	for _, c := range []struct {
		name, stderr string
		want         int
	}{
		{"just the banner", "debugfs 1.47.0 (5-Feb-2023)\n", 0},
		{"nothing at all", "", 0},
		{"a dump failure", "debugfs 1.47.0 (5-Feb-2023)\n" +
			"dump: Attempt to read block from filesystem resulted in short read while reading ext2 file\n", 1},
		{"an ls failure", "ls: File not found by ext2_lookup\n", 1},
		{"two of them", "dump: one\nstat: two\n", 2},
		// A workspace is allowed to contain a file called `dump:notes`, and
		// refusing on the substring would cost somebody their whole image. The
		// review asked for "any line containing"; com_err always writes the
		// command name first, so the prefix is both narrower and correct.
		{"a name that merely contains one", "reading /work/dump:notes went fine\n", 0},
		{"a usage line, which com_err does not write", "Usage: ls [-c] [-d] [-l] [-p] [-r] file\n", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := debugfsErrors(c.stderr); len(got) != c.want {
				t.Errorf("debugfsErrors(%q) = %v, want %d line(s)", c.stderr, got, c.want)
			}
		})
	}
}

// The two size comparisons are not one check written twice, and each is pinned
// on the thing only it can do.
//
// The Stat is about the staged copy and refuses *before* the destination is
// opened; the io.Copy count is about the bytes that actually reached the tree
// and covers the window between the two. Dropping either alone left the suite
// green, because for an ordinary file they see the same mismatch at two moments.
func TestF17_BothSizeComparisonsEarnTheirPlace(t *testing.T) {
	// The Stat: a mismatch must change nothing, not truncate the destination and
	// then complain. copyThrough opens with O_TRUNC, so without it the file in
	// the tree is already gone by the time the count is compared.
	t.Run("refused-before-the-destination-is-touched", func(t *testing.T) {
		tree := t.TempDir()
		const had = "what the tree already held\n"
		if err := os.WriteFile(filepath.Join(tree, "f.txt"), []byte(had), 0o644); err != nil {
			t.Fatal(err)
		}
		staged := filepath.Join(t.TempDir(), "0")
		if err := os.WriteFile(staged, []byte("short"), 0o644); err != nil {
			t.Fatal(err)
		}
		r, err := os.OpenRoot(tree)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()

		err = copyThrough(r, imageEntry{path: "f.txt", kind: kindFile, size: 100}, staged)
		if err == nil {
			t.Fatal("a staged file 95 bytes short of its record was installed")
		}
		if got, readErr := os.ReadFile(filepath.Join(tree, "f.txt")); readErr != nil ||
			string(got) != had {
			t.Errorf("the destination was opened O_TRUNC before the mismatch was noticed: "+
				"%q, %v", got, readErr)
		}
	})

	// The count: the staged file can disagree with its own Stat. A fifo is the
	// deterministic way to open that window — it stats as zero bytes and then
	// yields whatever is written to it — and it stands in for the general case,
	// a staged file whose length changes between the two calls.
	t.Run("the-copied-count-is-checked-too", func(t *testing.T) {
		dir := t.TempDir()
		fifo := filepath.Join(dir, "0")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skipf("this filesystem will not hold a fifo: %v", err)
		}
		info, err := os.Lstat(fifo)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != 0 {
			t.Skipf("a fifo stats as %d bytes here, so it does not open the window", info.Size())
		}
		go func() {
			w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				return
			}
			_, _ = w.Write([]byte("five!"))
			_ = w.Close()
		}()

		tree := t.TempDir()
		r, err := os.OpenRoot(tree)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		// The record says zero bytes, and Stat agrees, so only the count of what
		// was actually copied can catch this.
		if err := copyThrough(r, imageEntry{path: "f.txt", kind: kindFile, size: 0}, fifo); err == nil {
			got, _ := os.ReadFile(filepath.Join(tree, "f.txt"))
			t.Fatalf("%d bytes reached the workspace for an entry whose record says 0, and it "+
				"was accepted: %q", len(got), got)
		}
	})
}
