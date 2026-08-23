package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, rel, body string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// The comparison is against what was packed, so what it reports is what the
// sandbox did — not what has happened to the host directory since.
func TestCompareReportsWhatTheSandboxDid(t *testing.T) {
	before, after := t.TempDir(), t.TempDir()
	write(t, before, "keep.txt", "one\ntwo\nthree\n", 0o644)
	write(t, before, "gone.txt", "delete me\n", 0o644)
	write(t, before, "src/same.go", "package x\n", 0o644)

	entries, err := scanTree(before)
	if err != nil {
		t.Fatal(err)
	}
	m := &WorkspaceManifest{Schema: manifestSchema, Root: before, Entries: entries}

	write(t, after, "keep.txt", "one\nTWO\nthree\nfour\n", 0o644)
	write(t, after, "src/same.go", "package x\n", 0o644)
	write(t, after, "added.txt", "new\n", 0o644)

	oldRoot = before
	defer func() { oldRoot = "" }()
	changes, err := CompareTree(m, after)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]Change{}
	for _, c := range changes {
		got[c.Path] = c
	}
	if c, ok := got["added.txt"]; !ok || c.Kind != 'A' || c.Added != 1 {
		t.Errorf("added.txt = %+v, want A with one line", c)
	}
	if c, ok := got["gone.txt"]; !ok || c.Kind != 'D' {
		t.Errorf("gone.txt = %+v, want D", c)
	}
	if c, ok := got["keep.txt"]; !ok || c.Kind != 'M' || c.Added != 2 || c.Removed != 1 {
		t.Errorf("keep.txt = %+v, want M with +2 −1", c)
	}
	if _, ok := got["src/same.go"]; ok {
		t.Error("a file nothing touched was reported as a change")
	}
	if _, ok := got["src"]; ok {
		t.Error("a directory nothing touched was reported as a change")
	}
}

// A file whose contents are identical and whose mode changed is still a change,
// because it is one.
func TestAModeChangeIsAChange(t *testing.T) {
	before, after := t.TempDir(), t.TempDir()
	write(t, before, "run.sh", "#!/bin/sh\n", 0o644)
	entries, _ := scanTree(before)
	m := &WorkspaceManifest{Schema: manifestSchema, Root: before, Entries: entries}
	write(t, after, "run.sh", "#!/bin/sh\n", 0o755)

	changes, err := CompareTree(m, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != 'M' {
		t.Fatalf("changes = %+v, want one modification", changes)
	}
	if !strings.Contains(changes[0].Mode, "0644 → 0755") {
		t.Errorf("the change does not name the modes: %+v", changes[0])
	}
}

// lost+found is an ext4 artefact that appears on only one side, so leaving it
// in would report a deletion nobody made.
func TestTheFilesystemsOwnDirectoryIsNotAChange(t *testing.T) {
	before, after := t.TempDir(), t.TempDir()
	write(t, before, "a.txt", "x\n", 0o644)
	entries, _ := scanTree(before)
	m := &WorkspaceManifest{Schema: manifestSchema, Root: before, Entries: entries}
	write(t, after, "a.txt", "x\n", 0o644)
	write(t, after, "lost+found/whatever", "junk\n", 0o644)

	changes, err := CompareTree(m, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("changes = %+v, want none", changes)
	}
}

// Bytes that are not text report a size delta and say which, rather than a line
// count that would mean nothing.
func TestBinaryChangesReportBytes(t *testing.T) {
	before, after := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(before, "b.bin"), []byte{0, 1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	entries, _ := scanTree(before)
	m := &WorkspaceManifest{Schema: manifestSchema, Root: before, Entries: entries}
	if err := os.WriteFile(filepath.Join(after, "b.bin"), []byte{0, 1, 2, 3, 4, 5}, 0o644); err != nil {
		t.Fatal(err)
	}

	oldRoot = before
	defer func() { oldRoot = "" }()
	changes, err := CompareTree(m, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !changes[0].Binary || changes[0].Bytes != 2 {
		t.Fatalf("changes = %+v, want one binary change of +2 bytes", changes)
	}
	if !strings.Contains(FormatChanges(changes), "+2 bytes") {
		t.Errorf("the rendering does not say bytes:\n%s", FormatChanges(changes))
	}
}

// The line counts are a real longest-common-subsequence, not a length
// difference: a file that gained one line and lost another is +1 −1, not 0.
func TestTheLineCountsAreADiffAndNotASubtraction(t *testing.T) {
	a := []string{"one", "two", "three"}
	b := []string{"one", "TWO", "three"}
	if got := lcs(a, b); got != 2 {
		t.Errorf("lcs = %d, want 2 — so the counts read +1 −1", got)
	}
	if got := lcs(nil, b); got != 0 {
		t.Errorf("lcs against nothing = %d, want 0", got)
	}
	if got := lcs(a, a); got != 3 {
		t.Errorf("lcs with itself = %d, want 3", got)
	}
}
