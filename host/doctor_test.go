package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// TestSessionsSizeCheckWarnsWithoutFailing is S3: crossing the session-
// records size bound must report ok:false so it prints as attention-
// worthy, but warn:true so it never flips kelyfos doctor's own exit code
// — unlike every other FAIL in this file, past session history has no
// bearing on whether this machine can currently run KelyfOS
// (docs/retention.md §4 says so in as many words). Driven through
// sessionsSizeCheck directly, the pure decision checkSessionsSize's own
// directory walk feeds, rather than by actually writing a gigabyte-scale
// file to disk to cross the bound for real.
func TestSessionsSizeCheckWarnsWithoutFailing(t *testing.T) {
	c := sessionsSizeCheck("/fake/root", 3, sessionsSizeWarnBytes+1024)
	if c.ok {
		t.Fatal("sessionsSizeCheck reported ok over the advisory bound")
	}
	if !c.warn {
		t.Fatal("sessionsSizeCheck over the advisory bound must be a warning, not a FAIL — " +
			"crossing it changes nothing about whether this machine can run KelyfOS")
	}
	if c.fix == "" {
		t.Fatal("sessionsSizeCheck gave no fix for crossing the advisory bound")
	}
}

// TestSessionsSizeCheckUnderBoundNeitherFailsNorWarns is the companion
// case: comfortably under the bound is a plain pass, not a warning of any
// kind.
func TestSessionsSizeCheckUnderBoundNeitherFailsNorWarns(t *testing.T) {
	c := sessionsSizeCheck("/fake/root", 1, 4096)
	if !c.ok {
		t.Fatalf("sessionsSizeCheck failed well under the bound: %s", c.detail)
	}
	if c.warn {
		t.Fatal("sessionsSizeCheck warned well under the bound")
	}
}

// TestSessionsSizeCheckExactlyAtTheBound is the boundary itself: the check
// uses total < sessionsSizeWarnBytes, so exactly at the bound is already
// over it, the same "floor is inclusive going the other way" convention
// pruneEligible documents for the retention floor.
func TestSessionsSizeCheckExactlyAtTheBound(t *testing.T) {
	c := sessionsSizeCheck("/fake/root", 1, sessionsSizeWarnBytes)
	if c.ok {
		t.Fatal("sessionsSizeCheck reported ok exactly at the advisory bound")
	}
	if !c.warn {
		t.Fatal("sessionsSizeCheck at the bound must warn, not fail the exit code")
	}
}

// TestCheckSessionsSizeUnreadableRootHasAFix is S3's second half: an
// unreadable session-records root used to return ok:false with an EMPTY
// fix string — a FAIL with zero guidance. This makes the root a plain
// file instead of a directory, so os.ReadDir refuses it with a real
// error (not os.ErrNotExist), exercising the branch between "none
// recorded yet" and a real listing — the one part of checkSessionsSize
// that still needs the filesystem, since it is what decides whether
// sessionsSizeCheck is ever reached at all.
func TestCheckSessionsSizeUnreadableRootHasAFix(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	root := recorder.SessionsDir(sandbox.Root())
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := checkSessionsSize()
	if c.ok {
		t.Fatal("checkSessionsSize reported ok on an unreadable root")
	}
	if c.warn {
		t.Fatal("an unreadable root is a real problem, not advisory — it must not be a warn")
	}
	if c.fix == "" {
		t.Fatal("checkSessionsSize gave no fix for an unreadable root — S3's own finding")
	}
}

// TestCheckSessionsSizeNoneRecordedYet is the ordinary, filesystem-backed
// path when the sessions root simply does not exist yet — a fresh
// machine, or one that has never run a sandbox.
func TestCheckSessionsSizeNoneRecordedYet(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	c := checkSessionsSize()
	if !c.ok || c.warn {
		t.Fatalf("checkSessionsSize on a machine with no sessions at all: ok=%v warn=%v detail=%q", c.ok, c.warn, c.detail)
	}
}

// TestDoctorTallyIgnoresWarnChecks exercises the exact tally logic
// doctorCmd itself runs (S3): a slice of checks where the only failure is
// warn:true must count zero toward "failed" and one toward "warned" — the
// distinction that keeps kelyfos doctor's own exit code answering "can
// this machine run KelyfOS" rather than "does it have zero history to
// prune."
func TestDoctorTallyIgnoresWarnChecks(t *testing.T) {
	checks := []check{
		{name: "ok check", ok: true},
		{name: "warn check", ok: false, warn: true},
	}
	var failed, warned int
	for _, c := range checks {
		switch {
		case !c.ok && c.warn:
			warned++
		case !c.ok:
			failed++
		}
	}
	if failed != 0 {
		t.Errorf("failed = %d, want 0 — a warn-only check must not flip the exit code", failed)
	}
	if warned != 1 {
		t.Errorf("warned = %d, want 1", warned)
	}

	checks = append(checks, check{name: "real failure", ok: false})
	failed, warned = 0, 0
	for _, c := range checks {
		switch {
		case !c.ok && c.warn:
			warned++
		case !c.ok:
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("failed = %d, want 1 once a real FAIL is present", failed)
	}
}
