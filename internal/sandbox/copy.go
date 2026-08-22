package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// copyFile duplicates a file, preferring a reflink so a fork of a large
// workspace costs nothing on a filesystem that supports it.
//
// ext4 does not, so this silently becomes a full copy there — which is exactly
// why callers must check free space before forking N ways (P3-2).
func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := exec.Command("cp", "--reflink=auto", "--sparse=always", src, dst).Run(); err == nil {
		return nil
	}
	// cp is not guaranteed to exist or to support those flags; fall back.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// CheckForkSpace refuses a fork that cannot fit rather than failing partway
// through the third copy. On a filesystem without reflinks each fork is a full
// copy of the workspace image, so the cost is N times the size.
func CheckForkSpace(dir string, n int, perFork int64) error {
	if perFork <= 0 || n <= 0 {
		return nil
	}
	need := int64(n) * perFork
	free, err := freeBytes(dir)
	if err != nil {
		return nil
	}
	if free < need {
		return fmt.Errorf("%d forks need %d bytes of workspace copies in %s but only %d are free "+
			"(a filesystem without reflink support copies the whole image per fork)",
			n, need, dir, free)
	}
	return nil
}
