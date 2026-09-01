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
//
// The product n*perFork is computed without letting it wrap: n arrives from a
// client that once asked for MaxInt64 forks, and int64(n)*perFork over that
// ask reads negative, compares smaller than any free space, and waves the fork
// through (audit 2026-09-01, A1). The division proves the multiplication fits
// before it happens; a count the division refuses needs more than
// spaceNeedCeiling bytes, which no filesystem this could check has, so the
// refusal is made on the ceiling itself.
func CheckForkSpace(dir string, n int, perFork int64) error {
	if perFork <= 0 || n <= 0 {
		return nil
	}
	const spaceNeedCeiling = uint64(1) << 50 // 1 PiB
	need := spaceNeedCeiling
	if uint64(n) <= spaceNeedCeiling/uint64(perFork) {
		need = uint64(n) * uint64(perFork)
	}
	free, err := freeBytes(dir)
	if err != nil {
		return nil
	}
	if uint64(free) < need {
		return fmt.Errorf("%d forks need %d bytes of workspace copies in %s but only %d are free "+
			"(a filesystem without reflink support copies the whole image per fork)",
			n, need, dir, free)
	}
	return nil
}

// stageFile puts a file at dst without ever leaving a half-written one there.
//
// It exists because several forks of one snapshot stage the same read-only
// device at the same time: a plain copy would let one of them read what another
// was still writing, and a destination left read-only by whichever finished
// first would refuse the next outright. Copy to a temporary name in the same
// directory, then rename — which is atomic, and which succeeds over an existing
// read-only file because the permission that matters is the directory's.
func stageFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), filepath.Base(dst)+".stage-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	in, err := os.Open(src)
	if err != nil {
		tmp.Close()
		return err
	}
	_, err = io.Copy(tmp, in)
	in.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
