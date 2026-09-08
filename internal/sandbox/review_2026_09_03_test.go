package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The security review of 2026-09-03: a workspace image whose entries declare
// more content than the image can hold is refused before anything is staged,
// because the difference is a sparse file the host would otherwise
// materialise as zeros.

func TestReview_DeclaredSizeBeyondTheDiskIsRefused(t *testing.T) {
	img := filepath.Join(t.TempDir(), "workspace.ext4")
	if err := os.WriteFile(img, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := []imageEntry{
		{path: "small.txt", kind: kindFile, size: 10},
		{path: "hole.img", kind: kindFile, size: 1 << 30},
		{path: "dir", kind: kindDir},
	}
	err := declaredSizeFits(entries, stagingBytes(entries), img)
	if !errors.Is(err, ErrHostileImage) {
		t.Fatalf("want ErrHostileImage, got %v", err)
	}
	if !strings.Contains(err.Error(), "hole.img") {
		t.Errorf("the refusal should name the largest entry: %v", err)
	}
}

func TestReview_DeclaredSizeWithinTheDiskIsAccepted(t *testing.T) {
	img := filepath.Join(t.TempDir(), "workspace.ext4")
	if err := os.WriteFile(img, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	entries := []imageEntry{
		{path: "a", kind: kindFile, size: 4000},
		{path: "b", kind: kindSymlink, size: 12},
	}
	if err := declaredSizeFits(entries, stagingBytes(entries), img); err != nil {
		t.Fatalf("an image that fits was refused: %v", err)
	}
	// An image that cannot be stat'ed is not this check's to refuse; the
	// dump itself reports that.
	if err := declaredSizeFits(entries, stagingBytes(entries), filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("a missing image was refused here rather than by the dump: %v", err)
	}
}
