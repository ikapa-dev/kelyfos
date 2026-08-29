package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P7-17/B1 — the unit half, on resolveLeafLink itself.
//
// Separate from b1_test.go because that file is written to COMPILE against the
// parent commit and fail there on behaviour; resolveLeafLink does not exist
// there, so these two would have broken the build and turned five behavioural
// failures into one linker error.

// A loop is refused by name rather than followed until something else breaks.
func TestB1_ASymlinkLoopIsRefusedWithItsOwnMessage(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	_, err := resolveLeafLink(a)
	if err == nil {
		t.Fatal("a symlink loop resolved to something")
	}
	if !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), "chain") {
		t.Errorf("the refusal does not name the file and what is wrong with it: %v", err)
	}
}

// And an ordinary path is returned unchanged, so nothing about the common case
// went through the new walk and came out different.
func TestB1_AnOrdinaryPathResolvesToItself(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, filepath.Join(dir, "does-not-exist.json")} {
		got, err := resolveLeafLink(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got != p {
			t.Errorf("%s resolved to %s; an ordinary path must come back unchanged", p, got)
		}
	}
}
