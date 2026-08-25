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
// If the host directory changed since the image was packed, it refuses and
// writes beside it instead — "<dir>.kelyfos-out", or the first name after it
// that no earlier run's results are in. Overwriting an edit someone made in
// their editor would be the single most destructive thing this tool could do,
// and it would do it silently. "Since it was packed" rather than "while the
// sandbox was running" because Commit checks again at the last moment: with
// --review the sandbox has already stopped and the person is still typing.
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
		s.dest = divertedDest(w.HostDir)
		s.diverted = true
	}

	// Everything in the image was chosen by the guest, so it is read before it
	// is written: enumerated, validated entry by entry, and refused whole if any
	// entry is one the host cannot safely use (P6-24, extract.go).
	entries, err := listImage(w.ImagePath)
	if err != nil {
		return nil, err
	}

	// The dump has to land in an empty directory, and it is created before the
	// root is opened rather than by the root, because the root has to exist to
	// be opened.
	s.tree, err = stagingTree(w.HostDir)
	if err != nil {
		return nil, err
	}

	// debugfs reads the image without mounting it, so the write-back needs no
	// privileges. What it no longer does is choose where anything lands: it
	// dumps into staging files this package names, and every guest-chosen name
	// is used through the root below, which is openat2 with RESOLVE_BENEATH and
	// RESOLVE_NO_SYMLINKS underneath.
	root, err := os.OpenRoot(s.tree)
	if err != nil {
		_ = removeTree(s.tree)
		return nil, err
	}
	defer root.Close()
	if err := extractImage(w.ImagePath, entries, root); err != nil {
		_ = removeTree(s.tree)
		return nil, err
	}
	return s, nil
}

// Diverted reports that the host directory changed since the image was packed,
// so a commit will write beside it rather than over it. It is what Stage found;
// Commit looks again, because a review is a person and people take time.
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
	s.diverted = true
	dest, _, err := s.Commit()
	return dest, err
}

// Discard throws the extraction away without putting it anywhere.
func (s *Staged) Discard() { _ = removeTree(s.tree) }

// Commit puts the extracted tree where it belongs.
//
// It looks at the host directory again first, and that is the whole point of
// the function rather than a detail of it. Stage took its fingerprint before
// the review was shown, and a review is a person reading: the gap between the
// two is however long they took, and everything they edited in it lives in the
// directory this is about to rename away. Diverting here is the same answer
// Stage would have given had it been asked at the right moment, and it is the
// answer that keeps their work.
func (s *Staged) Commit() (dest string, diverted bool, err error) {
	w, tmp := s.w, s.tree
	if !s.diverted {
		// A fingerprint that cannot be taken is not evidence of no change, but
		// it is also not evidence of one, and refusing to write back a whole
		// session's work over a failed stat would be the worse mistake. Stage
		// treats an unreadable directory as fatal; by here the work exists and
		// the honest move is to proceed as Stage's own answer said.
		if now, ferr := Fingerprint(w.HostDir); ferr == nil && now != w.fingerprint {
			s.diverted = true
		}
	}
	if s.diverted {
		// The name is settled here, at the last moment, for the same reason the
		// fingerprint is taken again here: Stage chose while the review was
		// still ahead of it, and what is beside the directory can have changed
		// since. Choosing again costs nothing — a name that is still free is
		// still the first free one — so this is the path the review reported
		// unless something else has taken it in the meantime.
		s.dest = divertedDest(w.HostDir)
	}
	dest, diverted = s.dest, s.diverted

	// Swap rather than merge: the image is the authoritative post-run state, so
	// a file the agent deleted should be gone rather than resurrected. The old
	// copy is kept until the new one is in place.
	//
	// Only on the path that actually replaces something. A diverted commit
	// writes to a name of its own beside the project and takes nothing away, so
	// there is nothing here to rotate — and this ran regardless, which made the
	// run that deliberately left the project alone the run that deleted the
	// recoverable copy of it an earlier run had left behind (L-6). Declining a
	// review is the one answer that promises to touch nothing.
	old := w.HostDir + ".kelyfos-previous"
	if !diverted {
		_ = removeTree(old)
		if _, err := os.Stat(dest); err == nil {
			if err := os.Rename(dest, old); err != nil {
				return "", diverted, err
			}
		}
		// The tree takes the mode of the directory it replaces. Without this the
		// workspace root ends up with whatever this package created it as, which
		// is not what the person had, and before P6-24 it was whatever mode the
		// image's own root carried — a permission on somebody's project
		// directory chosen by the guest (H-2).
		//
		// The whole mode, not Perm(): this is the *person's own* previous
		// directory being copied forward, not anything the guest chose, and a
		// shared-group checkout keeps its root setgid on purpose. Perm() alone
		// dropped that, so files the person created in their project root
		// afterwards landed in the wrong group — silently, because scanTree
		// records Perm() and nothing would ever report it. (The guest's setuid
		// and setgid are refused elsewhere, in safeMode; the distinction is
		// whose mode it is.)
		//
		// Nothing to copy forward on the diverted path: there is no directory
		// being replaced, and the tree keeps the mode stagingTree gave it —
		// which is the mode this package has always created it with.
		if prev, err := os.Stat(old); err == nil {
			keep := prev.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
			_ = os.Chmod(tmp, prev.Mode().Perm()|keep)
		}
	}
	if err := os.Rename(tmp, dest); err != nil {
		if !diverted {
			// Put it back rather than leave nothing. Only where this moved it:
			// on the diverted path nothing was renamed away, and `old` is an
			// earlier run's backup — the person's own project — which this
			// would otherwise move to a name they were told holds sandbox
			// output.
			_ = os.Rename(old, dest)
		}
		return "", diverted, err
	}
	// The previous copy stays, until the next run that replaces the directory
	// clears it on the line above. It used to be deleted here, one statement
	// after the swap that made it worth having — a backup removed at the moment
	// it becomes useful is not a backup, and the person who wants it is the
	// person who has just watched a run overwrite something.
	s.tree = "" // moved into place; there is nothing left to discard
	return dest, diverted, nil
}

// stagingTree makes the directory an extraction dumps into, and gives it a name
// nothing else is using.
//
// Beside the host directory rather than in the system temp directory, because
// Commit finishes by renaming this tree into place and a rename cannot cross
// filesystems — /tmp very often is a different one, and a workspace that would
// only sync back on machines whose /tmp happens to be on the same disk is worse
// than one that never did.
//
// The name used to be one fixed `<dir>.kelyfos-sync`, cleared with a removeTree
// at the top of every Stage. Two sync-backs of one workspace therefore shared a
// directory — a team agent's max_runtime timer firing while a teardown is
// already stopping the same rig, or a second `kelyfos diff` against a workspace
// one is already staging — and the later one's removal unlinked the tree the
// earlier one was still extracting through an open root fd. What came out was a
// merged or half-written tree, and Commit would then put that over somebody's
// project (M-4).
//
// A fresh name per extraction is also why nothing here clears anything: the
// price is that a kelyfos killed mid-extraction leaves its staging tree beside
// the project instead of having it swept up by the next run, and that is the
// right trade — litter somebody can delete, rather than a live extraction
// deleted by a run that had no idea it was there.
//
// os.Mkdir at 0o755 rather than os.MkdirTemp, which hardcodes 0700. On the
// diverted path this directory is not scratch: it is renamed into place as the
// results directory the person is handed, so it has to be created the way
// os.MkdirAll(…, 0o755) created it before — mode from the caller, narrowed by
// their umask. Reaching for a temp-file constructor and inheriting a mode chosen
// for temp files is exactly how P6-18's exported reports became owner-only.
func stagingTree(hostDir string) (string, error) {
	// Bounded, because a loop that cannot end is not a better answer to a
	// directory this cannot create than an error is.
	for attempt := 0; attempt < 64; attempt++ {
		id, err := newID()
		if err != nil {
			return "", err
		}
		dir := hostDir + ".kelyfos-sync-" + id
		err = os.Mkdir(dir, 0o755)
		if err == nil {
			return dir, nil
		}
		if !os.IsExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("stage the workspace: no free staging directory beside %s", hostDir)
}

// divertedDest names the place a commit writes when it is not writing over the
// host directory: `<dir>.kelyfos-out`, then `<dir>.kelyfos-out.2`, and so on,
// the first one nothing is using.
//
// The first diversion still lands on `<dir>.kelyfos-out`. That is the name the
// documentation gives, the name the recipes grep, and the name somebody who has
// used this tool before will look for.
//
// It is the *second* one that was the bug. A fixed name is a name the next
// diverted run takes as well, and Commit rotates whatever is already at the
// destination into `<dir>.kelyfos-previous` — so three `run --review`s answered
// with n printed one path three times, and the third quietly deleted the first
// run's whole session on its way past. Nothing else keeps a copy: the workspace
// image is removed on the declined path too. Worse, the run that had it for one
// generation kept it under the one name whose documented meaning is the person's
// own previous project directory, which is where they would least look for
// sandbox output and most reasonably delete it unread (L-6).
func divertedDest(hostDir string) string {
	base := hostDir + ".kelyfos-out"
	for n := 1; n < 1000; n++ {
		dest := base
		if n > 1 {
			dest = fmt.Sprintf("%s.%d", base, n)
		}
		if _, err := os.Lstat(dest); os.IsNotExist(err) {
			return dest
		}
	}
	// A thousand of these beside one project is not a situation to fail a
	// sync-back over: refusing to write a session's work anywhere because the
	// tidy names are used up would be the worse answer.
	return fmt.Sprintf("%s.%d", base, time.Now().UnixNano())
}

// removeTree deletes a tree this package is finished with, including the
// read-only ones.
//
// os.RemoveAll cannot empty a directory that lacks owner-write, because
// unlinking a child needs write on the parent — and a workspace legitimately
// contains such directories: a vendored tree checked in at 0555 is an ordinary
// thing to have, and since the extraction stopped forcing u+rwx onto every
// directory it comes back the way it was packed. Left alone that fails silently,
// and what it leaves is a staging tree sitting beside somebody's project that
// nothing will ever come back for — each extraction has a name of its own now,
// so no later run sweeps up what an earlier one could not remove. Before they
// did, this was worse than litter: the next extraction wrote into the tree that
// had been left, and a run inherited files from the one before it.
//
// The unlocking is a retry rather than a first move, so nothing is touched in
// the ordinary case, and it is deliberately narrow. Of the two names this is
// ever pointed at, `<dir>.kelyfos-sync-*` is one kelyfos made, but
// `<dir>.kelyfos-previous` is **a directory kelyfos only renamed**: Commit moves
// whatever it is about to replace there — the person's own project, in the
// default flow — and leaves it as the recoverable copy of what a run overwrote.
//
// The first version of this walked the whole tree and chmodded every directory
// to 0700 — not only the ones that had refused an unlink, and dropping the
// group and other bits off the rest. Against a tree with a subdirectory the
// user cannot unlink at all (a root-owned node_modules a container left behind
// is the ordinary case) the removal then failed anyway, and what stayed on disk
// was the backup with its modes rewritten. So the rule here is: a directory is
// opened up only when its own mode is what stands in the way, and if it is
// still there when the removal is over, its mode goes back.
func removeTree(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	return removeUnlocking(dir)
}

// removeUnlocking removes one entry, unlocking a directory only where the
// directory's own mode is what refuses, and putting that mode back — including
// its setuid, setgid and sticky bits — if the directory survives the attempt
// anyway.
//
// It is a recursion rather than a walk because the decision is per directory
// and has to be undone per directory: a walk can see the modes but not which of
// them mattered.
func removeUnlocking(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.IsDir() {
		// Not a directory, so its own mode is not what refused — unlinking a
		// file needs write on its *parent*, and the parent is the frame above
		// this one, which has already made that decision for itself.
		return err
	}

	// u+rwx is what emptying a directory takes: read to list it, write and
	// execute to unlink what is inside. A directory that already has all three
	// is left exactly as it is, and nothing is lost by that: either it refused
	// nothing, or what refused was ownership rather than mode — the root-owned
	// node_modules a container left behind — and a chmod this user is not
	// allowed to make would have been refused too.
	// Perm() drops setuid, setgid and sticky, and chmod(2) takes the mode it is
	// given — so restoring Perm() alone silently clears them. One of the trees
	// this walks is `<dir>.kelyfos-previous`, the person's own previous project
	// directory kept as a recoverable backup, and a shared-group checkout keeps
	// its directories setgid on purpose. Stripping that is invisible: diff.go's
	// scanTree records Mode().Perm(), so nothing would ever report it, and the
	// person finds later that new files land in the wrong group. Carried
	// explicitly here for the same reason extractImage carries it (P6-28).
	special := info.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	perm := info.Mode().Perm()
	unlocked := false
	if perm&0o700 != 0o700 && os.Chmod(path, (perm|0o700)|special) == nil {
		unlocked = true
	}
	if entries, readErr := os.ReadDir(path); readErr == nil {
		for _, child := range entries {
			// Lstat above and os.Remove here, so a symlink to a directory is
			// unlinked rather than descended into.
			_ = removeUnlocking(filepath.Join(path, child.Name()))
		}
	}
	if err = os.Remove(path); err == nil {
		return nil
	}
	if unlocked {
		// Still on disk, so the mode this changed is a mode somebody is left
		// looking at — put back the whole mode, not only its permission bits.
		_ = os.Chmod(path, perm|special)
	}
	return err
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
