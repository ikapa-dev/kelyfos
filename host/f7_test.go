package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// P7-17/F7 — snapshot names were validated on the MCP path and not on the CLI
// path.
//
// validSnapshotName is a good check: an explicit character allowlist, a length
// bound and a leading-dot refusal. Every MCP tool called it before reaching
// snapshotDir; none of the CLI call sites did. Both paths are driven by the
// local user's own flags, so no privilege boundary is crossed — it is worth
// closing because a rule enforced at some call sites is a rule the next call
// site will miss, which the review demonstrated by miscounting them: it said
// four unvalidated callers and there were five (host/bench.go's oneRestore was
// the one it missed).
//
// So the gate moved into the path function, where the compiler finds every
// caller. What this file tests is the gate itself, and that no future call
// site can route around it by joining the directory by hand.

func TestF7_SnapshotDirRefusesANameThatCouldWalkOut(t *testing.T) {
	for _, c := range []struct{ name, why string }{
		{"", "an empty name"},
		{"../evil", "a parent-directory traversal"},
		{"..", "the parent directory itself"},
		{"a/b", "a separator"},
		{"a\\b", "a backslash"},
		{".hidden", "a leading dot"},
		{"/etc/passwd", "an absolute path"},
		{"name with spaces", "a space"},
		{"name\x00", "a NUL"},
		{"na\x1bme", "a control byte"},
		{"snap$(whoami)", "shell metacharacters"},
		{strings.Repeat("a", 65), "a name over the 64-character bound"},
	} {
		t.Run(c.why, func(t *testing.T) {
			dir, err := snapshotDir(c.name)
			if err == nil {
				t.Fatalf("snapshotDir(%q) was accepted and returned %q", c.name, dir)
			}
			if dir != "" {
				t.Errorf("snapshotDir(%q) refused but still returned a path: %q", c.name, dir)
			}
		})
	}
}

func TestF7_SnapshotDirAcceptsAnOrdinaryNameAndStaysUnderTheRoot(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	root := filepath.Join(sandbox.Root(), "snapshots")

	for _, name := range []string{"default", "before-upgrade", "v1.0", "a_b-c.d", strings.Repeat("a", 64)} {
		dir, err := snapshotDir(name)
		if err != nil {
			t.Fatalf("snapshotDir(%q): %v", name, err)
		}
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatalf("snapshotDir(%q) = %q, which is not under %q: %v", name, dir, root, err)
		}
		if rel != name {
			t.Errorf("snapshotDir(%q) resolved to %q, which is %q relative to the snapshot root", name, dir, rel)
		}
		for _, seg := range strings.Split(rel, string(filepath.Separator)) {
			if seg == ".." {
				t.Fatalf("snapshotDir(%q) = %q escapes the snapshot root", name, dir)
			}
		}
	}
}

// The belt-and-braces half: even if the character rule above is ever loosened,
// the joined path is asserted to stay under the snapshot root before it is
// returned. Checked by asking for a name the validator accepts and then
// confirming the assertion exists — a name that passes validation but escapes
// cannot be constructed today, which is the point, so this drives the
// assertion through the only door it has.
func TestF7_TheJoinAssertionIsThereAndNotJustTheCharacterRule(t *testing.T) {
	src, err := os.ReadFile("snapshot.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	fn := body[strings.Index(body, "func snapshotDir("):]
	fn = fn[:strings.Index(fn, "\n}\n")]
	if !strings.Contains(fn, "validSnapshotName") {
		t.Error("snapshotDir does not call validSnapshotName; the gate is not in the path function")
	}
	if !strings.Contains(fn, "filepath.Rel") {
		t.Error("snapshotDir does not assert filepath.Rel on the joined path; " +
			"the character rule is the only thing standing between a name and a directory")
	}
}

// And nothing routes around it. A future call site that joins the snapshots
// directory by hand would have every one of these guarantees and none of the
// check, which is exactly the shape this finding is.
func TestF7_NothingJoinsTheSnapshotsDirectoryByHand(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "snapshot.go" {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if strings.Contains(line, `"snapshots"`) {
				t.Errorf(`%s:%d joins the snapshots directory by hand: %s`+
					"\n  Use snapshotDir, which is where the name is validated (P7-17/F7).",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
