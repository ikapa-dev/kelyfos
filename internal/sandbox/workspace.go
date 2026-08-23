package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Workspace is a host directory made available inside the sandbox.
//
// Firecracker has no shared-filesystem device — no virtiofs, no 9p — so this is
// not a mount, it is a copy in and a copy out. The directory is packed into an
// ext4 image, attached as a second virtio-blk disk, and written back when the
// sandbox stops cleanly. That is the whole reason the design has to think about
// the host directory changing underneath it.
type Workspace struct {
	HostDir   string
	ImagePath string
	// fingerprint of the host directory when the image was packed, so a
	// concurrent edit can be detected rather than silently overwritten.
	fingerprint string
}

// workspaceMinSize is the floor for the image. A workspace that fits its
// contents exactly leaves the guest no room to build anything in it.
const workspaceMinSize = 1 << 30 // 1 GiB

// PackWorkspace builds an ext4 image from a host directory.
//
// mke2fs populates the image directly from the directory, so nothing has to be
// mounted and no privileges are needed — which matters because the alternative,
// loop-mounting as root, is exactly the kind of thing that makes a developer
// tool need sudo for no good reason.
func PackWorkspace(hostDir, imagePath string, maxSize int64) (*Workspace, error) {
	abs, err := filepath.Abs(hostDir)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("workspace %s: %w", hostDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace %s is not a directory", hostDir)
	}

	used, err := dirSize(abs)
	if err != nil {
		return nil, err
	}
	size := used * 2
	if size < workspaceMinSize {
		size = workspaceMinSize
	}
	if maxSize > 0 && size > maxSize {
		return nil, fmt.Errorf("workspace %s needs an image of %d bytes, over the %d byte ceiling; "+
			"raise it or exclude what does not need to be in the sandbox", hostDir, size, maxSize)
	}
	// Created before the free-space check rather than after: on a machine that
	// has never packed a workspace the directory does not exist yet, and
	// statfs on a path that is not there fails for a reason that has nothing to
	// do with free space.
	if err := os.MkdirAll(filepath.Dir(imagePath), 0o700); err != nil {
		return nil, err
	}
	if err := checkFreeSpace(filepath.Dir(imagePath), size); err != nil {
		return nil, err
	}
	_ = os.Remove(imagePath)
	// -d populates from a directory; -F because the target does not exist yet.
	out, err := exec.Command("mke2fs", "-q", "-t", "ext4", "-F",
		"-d", abs, imagePath, fmt.Sprintf("%dk", size/1024)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pack workspace: %w: %s", err, strings.TrimSpace(string(out)))
	}

	fp, err := Fingerprint(abs)
	if err != nil {
		return nil, err
	}
	// The manifest is recorded here because the walk has already happened and
	// this is the only moment the tree is known to be what was packed (E5-2).
	if err := writeWorkspaceManifest(abs, imagePath, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, fmt.Errorf("record the workspace manifest: %w", err)
	}
	return &Workspace{HostDir: abs, ImagePath: imagePath, fingerprint: fp}, nil
}

// AdoptWorkspace rebuilds a Workspace for an image whose packing happened in
// another process — a resumed session, whose disk was packed before a pause.
//
// The fingerprint is taken now rather than remembered, so what SyncBack compares
// against is the host directory as it was when this run adopted the image. That
// is the honest comparison for a resume: a change made while the session was
// paused is exactly the change a person needs to be told about, and it will be.
func AdoptWorkspace(hostDir, imagePath string) *Workspace {
	fp, _ := Fingerprint(hostDir)
	return &Workspace{HostDir: hostDir, ImagePath: imagePath, fingerprint: fp}
}

// SyncBack writes the workspace image back over the host directory.
//
// If the host directory changed while the sandbox was running, it refuses and
// writes to "<dir>.kelyfos-out" instead. Overwriting an edit someone made in
// their editor during the run would be the single most destructive thing this
// tool could do, and it would do it silently.
func (w *Workspace) SyncBack() (dest string, diverted bool, err error) {
	staged, err := w.Stage()
	if err != nil {
		return "", false, err
	}
	defer staged.Discard()
	return staged.Commit()
}

// Staged is an extracted workspace: the image's contents on the host, before
// anything has been put in place.
//
// It exists so a review can look at what came back and then decide, without
// extracting a multi-gigabyte image twice (E5-2).
type Staged struct {
	w        *Workspace
	tree     string
	dest     string
	diverted bool
}

// Stage extracts the image and works out where it would land.
func (w *Workspace) Stage() (*Staged, error) {
	now, err := Fingerprint(w.HostDir)
	if err != nil {
		return nil, err
	}
	s := &Staged{w: w, dest: w.HostDir}
	if now != w.fingerprint {
		s.dest = w.HostDir + ".kelyfos-out"
		s.diverted = true
	}

	// The dump has to land in an empty directory. debugfs rdump refuses to
	// descend into a subdirectory that already exists — it reports "File exists
	// while making directory" and carries on, which quietly leaves every nested
	// file at its pre-run contents while the top-level ones look updated. That
	// failure is worse than an error because it looks like success.
	s.tree = w.HostDir + ".kelyfos-sync"
	_ = os.RemoveAll(s.tree)
	if err := os.MkdirAll(s.tree, 0o755); err != nil {
		return nil, err
	}

	// debugfs reads the image without mounting it, so the write-back needs no
	// privileges. It does complain about being unable to restore ownership,
	// which is expected and harmless: files written by root in the guest come
	// back owned by whoever is running kelyfos.
	cmd := exec.Command("debugfs", "-R", "rdump / "+s.tree, w.ImagePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(s.tree)
		return nil, fmt.Errorf("read the workspace image: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// lost+found is an ext4 artefact, not the user's content.
	_ = os.RemoveAll(filepath.Join(s.tree, "lost+found"))
	return s, nil
}

// Diverted reports that the host directory changed while the sandbox ran, so a
// commit will write beside it rather than over it.
func (s *Staged) Diverted() (bool, string) { return s.diverted, s.dest }

// Changes is what the sandbox did to the workspace, against the manifest
// recorded when it was packed.
func (s *Staged) Changes() ([]Change, error) {
	m, err := ReadWorkspaceManifest(s.w.ImagePath)
	if err != nil {
		return nil, err
	}
	// The pre-run copy of each file, for the line counts. The host directory is
	// it, when nothing has edited it — and when something has, the diversion
	// above has already said so and the counts fall back to bytes.
	oldRoot = s.w.HostDir
	defer func() { oldRoot = "" }()
	return CompareTree(m, s.tree)
}

// Divert puts the extracted tree beside the host directory rather than over it,
// whatever the fingerprint said. It is what a declined review does: the host
// directory is untouched until somebody says yes, and the work is still there.
func (s *Staged) Divert() (string, error) {
	s.dest = s.w.HostDir + ".kelyfos-out"
	s.diverted = true
	dest, _, err := s.Commit()
	return dest, err
}

// Discard throws the extraction away without putting it anywhere.
func (s *Staged) Discard() { _ = os.RemoveAll(s.tree) }

// Commit puts the extracted tree where it belongs.
func (s *Staged) Commit() (dest string, diverted bool, err error) {
	w, tmp, dest, diverted := s.w, s.tree, s.dest, s.diverted
	// Swap rather than merge: the image is the authoritative post-run state, so
	// a file the agent deleted should be gone rather than resurrected. The old
	// copy is kept until the new one is in place.
	old := w.HostDir + ".kelyfos-previous"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(dest); err == nil {
		if err := os.Rename(dest, old); err != nil {
			return "", diverted, err
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Rename(old, dest) // put it back rather than leave nothing
		return "", diverted, err
	}
	_ = os.RemoveAll(old)
	s.tree = "" // moved into place; there is nothing left to discard
	return dest, diverted, nil
}

// Fingerprint summarises a directory tree: every path with its size and
// modification time. Cheap, and enough to notice that someone edited a file
// while the sandbox was running.
func Fingerprint(dir string) (string, error) {
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil // a file that vanished mid-walk is itself a change
		}
		lines = append(lines, fmt.Sprintf("%s|%d|%d", rel, info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}

func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// checkFreeSpace refuses up front rather than failing halfway through writing.
// This is also the check `kelyfos fork` needs once workspaces exist: N forks
// mean N copies when the filesystem cannot do reflinks.
func checkFreeSpace(dir string, need int64) error {
	free, err := freeBytes(dir)
	if err != nil {
		return nil // if we cannot tell, let the write fail honestly instead
	}
	if free < need {
		return fmt.Errorf("workspace image needs %d bytes in %s but only %d are free",
			need, dir, free)
	}
	return nil
}
