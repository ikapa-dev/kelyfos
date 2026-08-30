package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

func policyFrom(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), config.FileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the test's own policy does not parse: %v", err)
	}
	return cfg
}

// "The policy changed" tells somebody to go and diff two files. Naming the
// differences tells them whether they care, which is the whole point of the
// message (docs/qol.md §1.2).
func TestAResumeNamesWhatChanged(t *testing.T) {
	frozen := policyFrom(t, "[sandbox]\nimage = \"dev\"\nallow = [\"example.com\"]\n\n[resources]\ncpus = 2\nmem = \"512M\"\n")
	current := policyFrom(t, "[sandbox]\nimage = \"dev\"\nallow = [\"api.github.com\"]\n\n[resources]\ncpus = 4\nmem = \"512M\"\n")

	got := strings.Join(policyDifference(frozen, current), "; ")
	for _, want := range []string{"cpus 2 → 4", "allow gained api.github.com", "allow lost example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("the difference does not mention %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "mem") {
		t.Errorf("a value that did not change was reported as a difference:\n%s", got)
	}

	// The same file twice is no difference at all, whatever its formatting.
	same := policyFrom(t, "[resources]\ncpus = 2\n\n# a comment that changes nothing\nmem = \"512M\"\n")
	other := policyFrom(t, "[resources]\nmem  = \"512M\"\ncpus = 2\n")
	if diffs := policyDifference(same, other); len(diffs) > 0 {
		t.Errorf("reordering keys and adding a comment read as a change: %v", diffs)
	}
}

// A resume runs the frozen policy, so it must not be a way to carry an old
// ceiling past a new one — the hole E4-2 found in sandbox_restore (F-D39).
func TestAResumeCannotOutrunTheCurrentCeiling(t *testing.T) {
	frozen := policyFrom(t, "[sandbox]\nallow = [\"example.com\"]\n\n[resources]\ncpus = 8\nmem = \"2G\"\n")
	current := policyFrom(t, "[sandbox]\nallow = [\"example.com\"]\n\n[resources]\ncpus = 2\nmem = \"2G\"\n")

	err := frozenFitsCurrent("mig", frozen, current)
	if err == nil {
		t.Fatal("an 8 vcpu frozen policy resumed under a 2 vcpu ceiling")
	}
	for _, want := range []string{"cpus = 8", "ceiling of 2", "kelyfos.toml:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// Memory, and the allowlist, on the same rule.
	tight := policyFrom(t, "[sandbox]\nallow = [\"example.com\"]\n\n[resources]\ncpus = 8\nmem = \"512M\"\n")
	if frozenFitsCurrent("mig", frozen, tight) == nil {
		t.Error("a 2 GiB frozen policy resumed under a 512 MiB ceiling")
	}
	narrowed := policyFrom(t, "[sandbox]\nallow = [\"api.github.com\"]\n\n[resources]\ncpus = 8\nmem = \"2G\"\n")
	err = frozenFitsCurrent("mig", frozen, narrowed)
	if err == nil {
		t.Fatal("a frozen allowlist entry the project no longer permits was resumed")
	}
	if !strings.Contains(err.Error(), "example.com") {
		t.Errorf("the refusal does not name the domain:\n%v", err)
	}

	// And a policy that fits is not refused.
	if err := frozenFitsCurrent("mig", frozen, frozen); err != nil {
		t.Errorf("a policy identical to itself was refused: %v", err)
	}
	// With no policy in force there is no ceiling to exceed.
	if err := frozenFitsCurrent("mig", frozen, nil); err != nil {
		t.Errorf("with no current policy there is nothing to exceed, but: %v", err)
	}
}

// A session name becomes a directory, and `pause --as` is a thing a script can
// write as easily as a person.
func TestASessionNameCannotWalkOut(t *testing.T) {
	for _, bad := range []string{"", "..", "../evil", "a/b", ".hidden"} {
		if err := validSessionName(bad); err == nil {
			t.Errorf("%q was accepted as a session name", bad)
		}
	}
	if err := validSessionName(""); err == nil || !strings.Contains(err.Error(), "--as") {
		t.Errorf("an empty name does not say how to give one: %v", err)
	}
	for _, good := range []string{"before-the-migration", "v1.2_final", "p1"} {
		if err := validSessionName(good); err != nil {
			t.Errorf("%q is a reasonable name and was refused: %v", good, err)
		}
	}
}

// runningSandbox writes the state file `kelyfos pause` reads, under a cache
// root belonging to this test alone. Nothing boots and nothing needs to: the
// refusal below happens before the snapshot is taken, which is the point of
// making it there.
func runningSandbox(t *testing.T, st sandbox.State) {
	t.Helper()
	dir := sandbox.RunDirOf(st.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// RunDir is part of what a real machine writes, and readState checks the
	// record it finds against the directory it found it in (F19).
	st.RunDir = dir
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	// Beside the chroot, not inside it: the run directory is the VMM's own
	// filesystem root, and the host's record of a sandbox is not something the
	// VMM gets to rewrite (F19).
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "sandbox.json"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The two ends of a pause have to agree about what can come back. `resume`
// refuses a session whose snapshot recorded a NIC, and the snapshot layer
// records one for every machine that had a TAP — so a pause that does not ask
// the same question stops the machine, writes the whole session, and prints a
// resume command guaranteed to refuse. There is no second way in either:
// `snapshot restore` reads snapshots/<name>, and what a pause writes is
// named/<name>.
func TestAPauseRefusesTheMachineNoResumeCouldOpen(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	// The whole network block, because that is how a machine with a NIC is
	// recorded — New writes the six fields together or writes none of them, and
	// readState refuses half of them (F19). The id is eight hex characters for
	// the same reason a real one is: the interface name is derived from it.
	const egressID = "0901977d"
	runningSandbox(t, sandbox.State{ID: egressID, PID: os.Getpid(), Arch: "aarch64",
		Flavor: "dev", TAP: "kelyfos" + egressID, HostIP: "169.254.36.5", GuestIP: "169.254.36.6",
		Netmask: "255.255.255.252", HostMAC: "02:01:09:01:97:7d", ProxyPort: 41809,
		Allow: []string{"example.com"}})

	err := pauseCmd([]string{"--sandbox", egressID, "--as", "before-the-migration"})
	if err == nil {
		t.Fatal("a sandbox with egress was paused into a session nothing can bring back")
	}
	// What was in force, what state the machine is in, and the way that does
	// work — a refusal naming none of the three is a dead end with prose.
	for _, want := range []string{"example.com", "still running",
		"kelyfos snapshot save", "kelyfos snapshot restore", "before-the-migration"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "kelyfos resume before-the-migration") {
		t.Errorf("the refusal offers the one command that cannot work:\n%v", err)
	}
	// Refused before anything moved: no session on disk, and no marker telling
	// the run that owns this machine to skip its sync-back for ever.
	if _, err := os.Stat(namedDir("before-the-migration")); !os.IsNotExist(err) {
		t.Errorf("the refused pause left a stored session behind at %s", namedDir("before-the-migration"))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(sandbox.RunDirOf(egressID)), "paused")); !os.IsNotExist(err) {
		t.Error("the refused pause left the pause marker down, so the machine's own run would skip its sync-back")
	}

	// A machine with no NIC is the machine pause is for, and gets past this to
	// the snapshot it cannot take without a live VMM — which is a different
	// refusal, and proves this one did not fire.
	runningSandbox(t, sandbox.State{ID: "sb-quiet", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})
	err = pauseCmd([]string{"--sandbox", "sb-quiet", "--as", "t1"})
	if err == nil || strings.Contains(err.Error(), "egress") {
		t.Errorf("a sandbox with no network was refused a pause: %v", err)
	}
}

// needsImageTools skips when mke2fs and debugfs are absent, the same rule the
// extraction corpus in internal/sandbox applies to itself.
func needsImageTools(t *testing.T) {
	t.Helper()
	var missing []string
	for _, tool := range []string{"mke2fs", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) == 0 {
		return
	}
	if os.Getenv("KELYFOS_HOSTILE") == "required" {
		t.Fatalf("KELYFOS_HOSTILE=required and %s missing", strings.Join(missing, ", "))
	}
	t.Skipf("%s not installed", strings.Join(missing, ", "))
}

// captureStderr runs fn with os.Stderr pointed at a file and returns what was
// written. The message is part of the contract here: a person whose sync-back
// refused has to be told the work is still somewhere.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = f
	defer func() {
		os.Stderr = saved
		_ = f.Close()
	}()
	fn()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob)
}

// A refused write-back must not delete the workspace image, which is the only
// copy of what the sandbox did.
//
// syncResumedWorkspace registered `defer os.Remove(image)` before calling
// SyncBack, so the removal also ran on the error return. That was survivable
// only while a damaged image extracted silently and wrongly — the failure
// looked like success. F17 and F18 made it reachable: extraction now refuses an
// image whose dump came back short, and one carrying a symlink chain that
// leaves the workspace, so the defect that used to hand somebody a truncated
// file would instead have deleted their whole workspace. Strictly worse than
// the bug, and caused by the fix for it.
//
// Twenty lines above, the same function already states the rule the defer
// contradicted: "the directory on disk is worth more than the sync, and
// refusing is the only outcome that keeps it. Nothing was written back and
// nothing was removed."
func TestARefusedSyncBackKeepsTheWorkspaceImage(t *testing.T) {
	needsImageTools(t)

	// project builds the person's directory and an image packed from `content`,
	// and returns both. The image is a separate tree so the two can be made to
	// disagree.
	project := func(t *testing.T, content map[string]string) (root, hostDir, img string) {
		t.Helper()
		root = t.TempDir()
		hostDir = filepath.Join(root, "proj")
		if err := os.MkdirAll(hostDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(hostDir, "mine.txt"),
			[]byte("what the person had\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		src := filepath.Join(root, "src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range content {
			if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		img = filepath.Join(root, "ws.ext4")
		if out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
			"-d", src, img, "8192k").CombinedOutput(); err != nil {
			t.Fatalf("mke2fs: %v %s", err, out)
		}
		return root, hostDir, img
	}

	t.Run("refused-extraction-keeps-the-only-copy", func(t *testing.T) {
		root, hostDir, img := project(t, map[string]string{
			"work.txt": strings.Repeat("A", 1<<20),
		})
		// F17's own failure, on the path that used to delete the evidence: the
		// image is cut short, so the inode still reports 1048576 bytes and the
		// dump gives none of them. Extraction refuses.
		if err := os.Truncate(img, 2000<<10); err != nil {
			t.Fatal(err)
		}
		before, err := os.Stat(img)
		if err != nil {
			t.Fatal(err)
		}

		out := captureStderr(t, func() {
			syncResumedWorkspace(&sandbox.Sandbox{State: sandbox.State{Workspace: img}}, hostDir)
		})

		after, err := os.Stat(img)
		if err != nil {
			t.Fatalf("the refused sync-back deleted the workspace image, which was the only copy "+
				"of what the sandbox did: %v", err)
		}
		if after.Size() != before.Size() {
			t.Errorf("the image is %d bytes and was %d", after.Size(), before.Size())
		}
		// And the person's own directory is exactly as it was.
		if b, err := os.ReadFile(filepath.Join(hostDir, "mine.txt")); err != nil ||
			string(b) != "what the person had\n" {
			t.Errorf("the project was disturbed: %q, %v", b, err)
		}
		if _, err := os.Stat(filepath.Join(hostDir, "work.txt")); err == nil {
			t.Error("a refused extraction put a file from the image into the project anyway")
		}
		if _, err := os.Stat(hostDir + ".kelyfos-previous"); err == nil {
			t.Error("a refused extraction rotated the project away")
		}
		if beside, _ := filepath.Glob(hostDir + ".kelyfos-sync-*"); len(beside) != 0 {
			t.Errorf("a refused extraction left its staging tree behind: %v", beside)
		}
		// Being told is half of it: an image kept and never mentioned is an
		// image nobody knows to go and look for.
		for _, want := range []string{img, "nothing was removed", "only one"} {
			if !strings.Contains(out, want) {
				t.Errorf("the refusal does not mention %q:\n%s", want, out)
			}
		}
		_ = root
	})

	// The other half, unchanged: a sync-back that actually happened still clears
	// the image up. The removal sits above the diverted branch, so both outcomes
	// of a completed sync-back behave exactly as they did before.
	t.Run("a-sync-back-that-happened-still-removes-it", func(t *testing.T) {
		_, hostDir, img := project(t, map[string]string{"work.txt": "what the agent did\n"})

		syncResumedWorkspace(&sandbox.Sandbox{State: sandbox.State{Workspace: img}}, hostDir)

		if _, err := os.Stat(img); !os.IsNotExist(err) {
			t.Errorf("a completed sync-back left the image behind (%v); it is a duplicate of what "+
				"is now on disk and the session is over", err)
		}
		if b, err := os.ReadFile(filepath.Join(hostDir, "work.txt")); err != nil ||
			string(b) != "what the agent did\n" {
			t.Errorf("the work did not reach the project: %q, %v", b, err)
		}
		// The swap happened: what was there before is the recoverable copy.
		if b, err := os.ReadFile(filepath.Join(hostDir+".kelyfos-previous", "mine.txt")); err != nil ||
			string(b) != "what the person had\n" {
			t.Errorf("the previous copy is not there: %q, %v", b, err)
		}
	})

	// The neighbouring rule this one now matches, kept honest: an image that is
	// missing or empty is refused before any of the above, and nothing is
	// removed there either.
	t.Run("an-unreadable-image-changes-nothing", func(t *testing.T) {
		_, hostDir, img := project(t, map[string]string{"work.txt": "x\n"})
		if err := os.Truncate(img, 0); err != nil {
			t.Fatal(err)
		}
		out := captureStderr(t, func() {
			syncResumedWorkspace(&sandbox.Sandbox{State: sandbox.State{Workspace: img}}, hostDir)
		})
		if _, err := os.Stat(img); err != nil {
			t.Errorf("the empty image was removed: %v", err)
		}
		if b, err := os.ReadFile(filepath.Join(hostDir, "mine.txt")); err != nil ||
			string(b) != "what the person had\n" {
			t.Errorf("the project was disturbed: %q, %v", b, err)
		}
		if !strings.Contains(out, "nothing was removed") {
			t.Errorf("the refusal does not say so:\n%s", out)
		}
	})
}

// `kelyfos diff` reads a disk the guest is still writing to, and the extraction
// refuses an image that does not agree with itself.
//
// Those two facts together made F17's fix a regression on the most-used
// read-only command: enumeration and dumping are separate debugfs processes, so
// any file the agent appends to between them has a recorded size that no longer
// matches, and the person got "the workspace image contains an entry this host
// will not use … the dump did not finish, so nothing from this image is written
// back" on a command whose own help says it shows what has reached the disk.
// Before this branch they got a slightly stale file.
//
// Nothing in the extraction is softened for it — the same code writes the
// workspace back at teardown, and a read-only mode would be a second, weaker
// set of rules for the same bytes. It reads again instead.
func TestDiffReadsAgainWhenTheWorkspaceIsBeingWrittenTo(t *testing.T) {
	hostile := fmt.Errorf("%w: work.txt came out of the image as 40 bytes and its record says 32",
		sandbox.ErrHostileImage)

	t.Run("a-transient-disagreement-is-read-again", func(t *testing.T) {
		calls := 0
		_, err := stageTwice(func() (*sandbox.Staged, error) {
			calls++
			if calls == 1 {
				return nil, hostile
			}
			return nil, nil
		})
		if err != nil {
			t.Fatalf("a file that grew between the two passes was reported as a hostile image: %v", err)
		}
		if calls != 2 {
			t.Errorf("stage was called %d time(s), want 2", calls)
		}
	})

	t.Run("a-clean-read-is-not-repeated", func(t *testing.T) {
		calls := 0
		if _, err := stageTwice(func() (*sandbox.Staged, error) {
			calls++
			return nil, nil
		}); err != nil {
			t.Fatal(err)
		}
		if calls != 1 {
			t.Errorf("stage was called %d time(s) for an image that read cleanly, want 1", calls)
		}
	})

	t.Run("twice-is-still-a-refusal-and-says-why", func(t *testing.T) {
		calls := 0
		_, err := stageTwice(func() (*sandbox.Staged, error) {
			calls++
			return nil, hostile
		})
		if err == nil {
			t.Fatal("an image that contradicted itself twice was accepted")
		}
		if calls != 2 {
			t.Errorf("stage was called %d time(s), want 2", calls)
		}
		if !errors.Is(err, sandbox.ErrHostileImage) {
			t.Errorf("the refusal stopped wrapping ErrHostileImage: %v", err)
		}
		// Both readings, because the command cannot tell them apart and the
		// person can.
		for _, want := range []string{"still writing to", "Try again", "the image itself"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q:\n%v", want, err)
			}
		}
	})

	// A refusal that is not about the image — a missing file, a bad manifest —
	// is passed straight back rather than retried and reworded.
	t.Run("an-unrelated-failure-is-not-retried", func(t *testing.T) {
		calls := 0
		other := errors.New("no such file or directory")
		_, err := stageTwice(func() (*sandbox.Staged, error) {
			calls++
			return nil, other
		})
		if !errors.Is(err, other) {
			t.Errorf("the error came back as %v", err)
		}
		if calls != 1 {
			t.Errorf("stage was called %d time(s) for an unrelated failure, want 1", calls)
		}
	})
}
