package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P7-17/F21, the verification round: nothing tested the ownership half.
//
// Trust has two rules. The writability half is covered from several angles,
// because a test can chmod. The ownership half was covered from none, because a
// test cannot chown: every fixture in this package writes its file as the
// invoking user, so `uid == me` on every path any of them takes. trustOwner
// could have been `return nil` and the whole suite would still have been green
// — which is the same shape as the fourteen tests this task found unable to
// fail, one layer further down.
//
// Two answers, because either alone is weak. The decision is pulled out into
// ownedByCaller and driven on explicit inputs, which is the precedent
// privateGroup set in this file for exactly this reason; and Trust itself is
// driven against a real file on this machine that a third uid owns, when the
// machine has one.

func TestF21_OwnedByCallerRefusesAThirdUid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uid, me int
		want    bool
	}{
		{"my own file", 1000, 1000, true},
		{"a root-owned file", 0, 1000, true},
		{"another user's file", 1001, 1000, false},
		{"a service account's file", 104, 1000, false},
		{"root's own file, running as root", 0, 0, true},
		{"another user's file, running as root", 1000, 0, false},
	} {
		if got := ownedByCaller(tc.uid, tc.me); got != tc.want {
			t.Errorf("%s: ownedByCaller(uid=%d, me=%d) = %v, want %v",
				tc.name, tc.uid, tc.me, got, tc.want)
		}
	}
}

// foreignOwnedFile finds a readable regular file on this machine owned by a uid
// that is neither root nor the invoking user, so the refusal can be driven
// through the real Trust rather than through its arithmetic.
//
// A skip and not a failure where there is none: a container or a fresh CI image
// can legitimately have no third uid owning anything. Saying so is the point —
// a fixture that quietly passes because it found nothing to test is what this
// whole review round is about.
func foreignOwnedFile(t *testing.T) string {
	t.Helper()
	me := os.Getuid()
	for _, root := range []string{"/var/log", "/var/lib", "/var/spool", "/run"} {
		var found string
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || found != "" {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			uid, ok := fileUID(info)
			if !ok || uid == 0 || uid == me {
				return nil
			}
			// Not group- or world-writable, so the writability rule does not
			// answer first and hide the one being measured.
			if writableByOthers(info) != "" {
				return nil
			}
			found = path
			return fs.SkipAll
		})
		if found != "" {
			return found
		}
	}
	t.Skip("no readable file on this machine is owned by a third uid, so the ownership " +
		"rule cannot be driven end to end here; TestF21_OwnedByCallerRefusesAThirdUid " +
		"covers the decision itself")
	return ""
}

func TestF21_ADiscoveredPolicyOwnedByAnotherUserIsRefused(t *testing.T) {
	path := foreignOwnedFile(t)

	// Re-checked here, immediately before the assertion, because the file was
	// chosen by a walk over /var/log and /run and a log can rotate between the
	// two (P7-17/A1, review round). Trust returns nil when os.Stat fails, so a
	// file that vanished would be reported as "trusted" — a false failure with
	// a message pointing at the wrong thing. A skip is the honest answer.
	fi, err := os.Stat(path)
	if err != nil {
		t.Skipf("%s went away between being chosen and being tested (%v); nothing to measure",
			path, err)
	}
	if uid, ok := fileUID(fi); !ok || uid == 0 || uid == os.Getuid() {
		t.Skipf("%s changed owner between being chosen and being tested; nothing to measure", path)
	}

	err = Trust(path, true)
	if err == nil {
		t.Fatalf("a discovered policy at %s, which this user does not own, was trusted", path)
	}
	for _, want := range []string{path, "--policy"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// And the hatch still works, which is the half the rule deliberately does
	// not close: naming a file is the decision the ownership rule asks for.
	if err := Trust(path, false); err != nil {
		t.Errorf("--policy is the escape hatch for ownership and it refused anyway: %v", err)
	}
}
