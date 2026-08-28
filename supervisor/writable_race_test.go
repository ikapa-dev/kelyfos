package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// F11 (security review of 2026-08-28) — write_file re-checks for symlinks and
// then opens through one anyway.
//
// The supervisor's file tools run in PID 1, which is not confined, so the tree
// check bounds a path to a writable tree and refuses one whose components are
// symlinks. The comment on the second check is candid about why it is there: "a
// symlink can be planted in the gap between that decision and this call." But
// the second check is the same lexical Lstat walk as the first, and what follows
// it was an ordinary os.MkdirAll and os.WriteFile — both of which resolve
// symlinks, neither of which is atomic with the check.
//
// The gap is not narrow. noSymlinksBeneath returns nil at the *first component
// that does not exist*, on the correct reasoning that nothing missing can be a
// symlink. For a file being created — which is the ordinary case for write_file
// — that means the check returns immediately, and the window to the open is the
// whole of MkdirAll. A confined exec holds MAKE_SYM on every tree it can write,
// so
//
//	while :; do rm -f /work/x; ln -s /dev/vdb /work/x; rm -f /work/x; done
//
// in the background is all it costs, and on the iteration where the link exists
// at the open, PID 1 writes the agent's bytes wherever it points.
//
// This test races it rather than planting it. A planted link is what the F1
// fixture already covers and what the lexical walk does catch; the finding is
// the swap, and a fixture that plants cannot fail on it.

// f11Payload is what the writer writes. If it ever appears in the victim, the
// tool wrote through a symlink that left every tree a sandbox may write.
const f11Payload = "owned by the guest via F11\n"

func TestF11_WriteFileCannotBeRacedThroughASymlink(t *testing.T) {
	// The victim is under /var/tmp: outside every tree writableEverywhere
	// names, and safe to lose on a shared machine — which /dev/vdb, the real
	// target, is not. This process runs unconfined exactly as the supervisor
	// does, so a bug in the fix makes the write land rather than fail
	// differently, and the fixture must not be able to reach anything that
	// matters.
	victimDir, err := os.MkdirTemp("/var/tmp", "kelyfos-f11-victim-*")
	if err != nil {
		t.Skipf("could not stage the escape target under /var/tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(victimDir) })
	victim := filepath.Join(victimDir, "victim")
	if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The writable side is under /tmp, which writableEverywhere names, so the
	// tool's own "where" check passes and what is being measured is the race
	// rather than the tree test.
	treeDir, err := os.MkdirTemp("/tmp", "kelyfos-f11-tree-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(treeDir) })
	target := filepath.Join(treeDir, "x")

	var stop atomic.Bool
	flips := make(chan struct{})
	go func() {
		defer close(flips)
		for !stop.Load() {
			// The three states the check cannot tell apart in time: absent,
			// which makes noSymlinksBeneath return nil at once; a symlink out
			// of the tree, which is what the open must refuse; and absent
			// again, so the next iteration starts clean.
			os.Remove(target)
			_ = os.Symlink(victim, target)
			os.Remove(target)
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	writes := 0
	for i := 0; i < 200000 && time.Now().Before(deadline); i++ {
		writeFile(target, []byte(f11Payload), 0o644)
		writes++
	}
	stop.Store(true)
	<-flips

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("the victim file is gone, which is its own kind of write-through: %v", err)
	}
	if strings.Contains(string(got), f11Payload) {
		t.Fatalf("write_file wrote through a symlink planted between its check and its open:\n"+
			"  %s holds the guest's bytes after %d writes\n"+
			"  It is outside every tree writableEverywhere names. On a real guest the link would point at\n"+
			"  /dev/vdb and this would be a raw write to the workspace disk.", victim, writes)
	}
	if writes < 1000 {
		t.Errorf("only %d writes were attempted; this fixture proves nothing at that rate", writes)
	}
	t.Logf("%d writes raced against a symlink flip; the victim was never touched", writes)
}

// The same race against upload, which shares writeFile with write_file. Cheap to
// state and it pins the sharing: if somebody gives upload its own write path,
// this fails rather than silently losing the protection.
func TestF11_UploadSharesTheSameGuardedWrite(t *testing.T) {
	victimDir, err := os.MkdirTemp("/var/tmp", "kelyfos-f11-upload-victim-*")
	if err != nil {
		t.Skipf("could not stage the escape target under /var/tmp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(victimDir) })
	victim := filepath.Join(victimDir, "victim")
	if err := os.WriteFile(victim, []byte("untouched\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	treeDir, err := os.MkdirTemp("/tmp", "kelyfos-f11-upload-tree-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(treeDir) })
	target := filepath.Join(treeDir, "x")

	if err := os.Symlink(victim, target); err != nil {
		t.Fatal(err)
	}
	// Pre-existing rather than raced, because what this asserts is that upload
	// goes through the same door — the race above covers the timing.
	res := writeFile(target, []byte(f11Payload), 0o644)
	if res == nil {
		t.Errorf("writeFile followed a pre-existing symlink out of the tree")
	}
	if got, err := os.ReadFile(victim); err == nil && strings.Contains(string(got), f11Payload) {
		t.Errorf("the guest's bytes reached %s through the symlink at %s", victim, target)
	}
}

// The other direction, which the fix must not break: a symlink that stays inside
// the same writable tree is still refused by name, and an ordinary write still
// works. An *os.Root follows a relative in-tree link — its walk only refuses one
// that leaves the tree — so this pins that the lexical refusal in writableTarget
// is still in front of it and no existing refusal was traded away for the atomic
// one.
func TestF11_OrdinaryWritesStillWorkAndInTreeSymlinksAreStillRefused(t *testing.T) {
	treeDir, err := os.MkdirTemp("/tmp", "kelyfos-f11-ok-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(treeDir) })

	plain := filepath.Join(treeDir, "sub", "dir", "file.txt")
	if res := writeFile(plain, []byte("hello\n"), 0o644); res != nil {
		t.Fatalf("an ordinary write into /tmp was refused: %s", resultText(res))
	}
	if got, err := os.ReadFile(plain); err != nil || string(got) != "hello\n" {
		t.Fatalf("the ordinary write did not land: %q %v", got, err)
	}

	real := filepath.Join(treeDir, "real.txt")
	if err := os.WriteFile(real, []byte("real\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(treeDir, "link.txt")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	res := writeFile(link, []byte("through the link\n"), 0o644)
	if res == nil {
		t.Errorf("a symlink inside the tree was written through; the tree check refused these before F11 " +
			"and F11 must not have traded that refusal for the atomic one")
	} else if !mentions(resultText(res), "symlink") {
		t.Errorf("it was refused, but not as a symlink, so the message got worse: %s", resultText(res))
	}

	// A write aimed at a writable tree itself. It has always failed and must
	// keep failing as what it is — a directory — rather than as "outside the
	// trees a sandbox may write", which would be a false statement about /tmp.
	res = writeFile("/tmp", []byte("x"), 0o644)
	if res == nil {
		t.Errorf("writing to /tmp itself was accepted")
	} else if mentions(resultText(res), "outside the trees") {
		t.Errorf("writing to /tmp was refused as being outside the writable trees, which it is not: %s",
			resultText(res))
	} else if !mentionsAny(resultText(res), "directory", "isdir") {
		t.Errorf("writing to /tmp was refused, but not as a directory: %s", resultText(res))
	}

	// The named device nodes take the other branch of the fix — an exact path
	// from a fixed list, opened O_NOFOLLOW because there is no tree to be
	// beneath — so they need saying separately or the branch is untested.
	if _, err := os.Stat("/dev/null"); err == nil {
		if res := writeFile("/dev/null", []byte("x"), 0o644); res != nil {
			t.Errorf("/dev/null is on the profile's writable list and the tools refused it: %s", resultText(res))
		}
	}
}
