package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Where the supervisor's own file tools may write (P6-24, finding H-1).
//
// The supervisor is PID 1 and it is not confined by the profile it applies to
// everything it spawns: applyLandlock and applySeccomp are reached only from the
// re-exec'd --confine helper, so a tool running inside PID 1 has the whole
// filesystem in front of it. write_file passed the agent's path straight to
// os.WriteFile — no Clean, no IsLocal, no root to be beneath — and the schema
// string saying "Absolute path inside the sandbox" was enforced by nothing.
//
// What that bought an agent is named in profile.go's own comment, three lines
// above the list it is explaining:
//
//	Granting /dev would have fixed that and also handed an agent /dev/vda and
//	/dev/vdb — the raw block devices behind the read-only root and the
//	workspace — so the list is explicit and the disks are not on it.
//
// The profile withholds those two from every process the supervisor starts, and
// the supervisor's own tool handed them over. So the rule here is not a new
// policy invented for the occasion: **the tools get exactly the reach the
// profile gives a confined child**, and PID 1 stops being a way around the
// confinement it enforces.
//
// Reads are deliberately not restricted, and that is not an oversight. The
// profile grants read beneath / to confined children — allowBeneath(rules, "/",
// readRights) — so anything read_file can reach, a spawned process can reach
// too. Restricting reads would make the tool weaker than the thing it exists to
// serve while closing nothing, and it would break reading /etc/os-release and
// /proc. The asymmetry in the profile is the asymmetry here.

// writeTarget is where a write has been allowed to land, in the form the write
// itself needs: a tree to anchor an *os.Root at and the path relative to it, or
// one of the named device nodes, to be opened by exact name.
//
// The write path needs the tree and not only a yes, which is the shape F11
// changed. A check that answers "yes" and hands back the same absolute string it
// was given leaves the caller to open that string, and an open of an absolute
// string resolves whatever the filesystem says at that moment — which is not
// what was checked.
type writeTarget struct {
	tree string // the writable tree to anchor a root at, "" for a device node
	rel  string // the path within that tree
	dev  string // the exact device node, "" for a tree write
}

// writableTarget reports where a write may land, or why it may not.
//
// The comparison is against the same three lists the profile is built from, so
// the two cannot drift into disagreeing about what a sandbox may write. It
// replaced a writableFor that answered only yes or no: F11 needed the tree as
// well, because a decision about a path is worth nothing to a caller that then
// opens the path by name.
//
// One residual it does not cover, stated because it is invisible otherwise.
// Go's *os.Root refuses a component that leaves the tree, but it does **not**
// stop at a mount boundary — a bind mount underneath a writable tree would be
// walked into as ordinary directories. Nothing is mounted beneath /work, /tmp,
// /run or /root in this image (/work is itself the mount, which is the anchor
// rather than something below it), so there is no exposure today; a future
// submount under one of these trees would need this reading again.
func writableTarget(path string) (writeTarget, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return writeTarget{}, fmt.Errorf("%q is not an absolute path; the tools write to absolute paths inside the sandbox, "+
			"and a relative one means whatever directory the supervisor happens to be in", path)
	}
	// Kept in front of the open, and no longer the thing that makes the write
	// safe — that is the *os.Root in writeFile now (F11). What this still buys
	// is the message: a link planted and left in place is named here, as a
	// symlink and by component, where the root walk can only say that the path
	// left its root. It also keeps the refusal this project already documented
	// for a relative in-tree link, which that walk would follow.
	if err := noSymlinksBeneath(clean); err != nil {
		return writeTarget{}, err
	}
	for _, tree := range writableEverywhere {
		if rel, ok := within(clean, tree); ok {
			return writeTarget{tree: tree, rel: rel}, nil
		}
	}
	for _, tree := range writableDeviceTrees {
		if rel, ok := within(clean, tree); ok {
			return writeTarget{tree: tree, rel: rel}, nil
		}
	}
	for _, dev := range writableDevices {
		if clean == dev {
			return writeTarget{dev: dev}, nil
		}
	}
	return writeTarget{}, fmt.Errorf("%s is outside the trees a sandbox may write (%s). "+
		"The confinement profile withholds everything else from every process this supervisor starts, "+
		"including the raw disks behind the root filesystem and the workspace, and the file tools do not "+
		"get to be the way around it",
		clean, strings.Join(writableEverywhere, ", "))
}

// noSymlinksBeneath refuses a path that carries a symlink in any component,
// including a pre-existing symlink at the final component (finding F1).
//
// Since F11 this is a message and a second opinion, not the guard. See the
// paragraph below, and writeFile in tools.go for what does the guarding.
//
// beneath is a pure string/prefix decision, and creating a symlink costs
// nothing a confined exec doesn't already have: LANDLOCK_ACCESS_FS_MAKE_SYM is
// granted on every tree write is, alongside it. "ln -s /dev/vda /work/escape"
// is therefore one command away from any confined agent, and write_file(path)
// handed straight to os.WriteFile follows it exactly like open(2) does — the
// lexical check above never looks past the name to ask what it points at, so
// /work/escape reads as beneath /work right up until the kernel resolves it
// onto the raw disk behind the read-only root.
//
// This was written as the same discipline extract.go's host-side workspace
// extraction already uses — a symlink is never resolved through, on the way to a
// write — worked by hand rather than through an *os.Root, on the reasoning that
// the file tools address the whole filesystem by absolute path across five
// writable trees and a list of exact device nodes, not one tree opened once, so
// there was no single root to anchor.
//
// *That reasoning was wrong, and F11 of the 2026-08-28 review is what it cost.*
// There is no single root, but there does not need to be: writableTarget already
// decides which tree a path belongs to, and that tree is a root to anchor for
// this write. Stating the rule by hand made it lexical, and a lexical rule is a
// statement about names at the moment it runs, while the write is a statement
// about the filesystem at the moment it opens. Between the two, a confined exec
// holding MAKE_SYM could put a link where the name had just been checked. The
// write is now done through an *os.Root, which walks the path one component at a
// time with openat(O_NOFOLLOW) against a directory handle it already holds — see
// writeFile in tools.go for what that does and does not mean — and this walk
// stays in front of it for the error message and for the relative in-tree link
// the root walk would follow.
//
// The rule it states is still the rule: nothing along the way is allowed to be a
// symlink, existing or not. It is simply no longer the thing enforcing it.
func noSymlinksBeneath(path string) error {
	clean := filepath.Clean(path)
	cur := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			// Nothing here yet. write_file creates the target itself and
			// MkdirAll creates whatever parents are missing, and a component
			// that does not exist cannot be a symlink — and nothing can exist
			// beneath a component that is itself missing, so there is nothing
			// further along the path left to check.
			if os.IsNotExist(err) {
				return nil
			}
			return fmt.Errorf("checking whether %s is a symlink: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; the file tools refuse to write through one component of a "+
				"path — planted by the sandbox or not — rather than trust where it leads", cur)
		}
	}
	return nil
}

// within is beneath, plus the relative path an *os.Root needs.
//
// The tree itself comes back as ".", which is deliberate: writing to /tmp is a
// write to a directory, and the honest answer to it is the kernel's EISDIR from
// the open, not "outside the trees a sandbox may write" — which would be false,
// and is the message this would otherwise fall through to.
func within(path, tree string) (string, bool) {
	if !beneath(path, tree) {
		return "", false
	}
	rel, err := filepath.Rel(tree, path)
	if err != nil {
		return "", false
	}
	return rel, true
}

// beneath is the path test, done on components rather than on strings.
//
// A prefix comparison would let /workspace-of-somebody-else pass for being
// beneath /work, which is the oldest mistake in this shape of check.
func beneath(path, tree string) bool {
	if path == tree {
		return true
	}
	rel, err := filepath.Rel(tree, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, "../")
}
