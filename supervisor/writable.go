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

// writableFor reports why a path may not be written, or nil if it may.
//
// The comparison is against the same three lists the profile is built from, so
// the two cannot drift into disagreeing about what a sandbox may write.
func writableFor(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("%q is not an absolute path; the tools write to absolute paths inside the sandbox, "+
			"and a relative one means whatever directory the supervisor happens to be in", path)
	}
	if err := noSymlinksBeneath(clean); err != nil {
		return err
	}
	for _, tree := range writableEverywhere {
		if beneath(clean, tree) {
			return nil
		}
	}
	for _, tree := range writableDeviceTrees {
		if beneath(clean, tree) {
			return nil
		}
	}
	for _, dev := range writableDevices {
		if clean == dev {
			return nil
		}
	}
	return fmt.Errorf("%s is outside the trees a sandbox may write (%s). "+
		"The confinement profile withholds everything else from every process this supervisor starts, "+
		"including the raw disks behind the root filesystem and the workspace, and the file tools do not "+
		"get to be the way around it",
		clean, strings.Join(writableEverywhere, ", "))
}

// noSymlinksBeneath refuses a path that carries a symlink in any component,
// including a pre-existing symlink at the final component (finding F1).
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
// This is the same discipline extract.go's host-side workspace extraction
// already uses — a symlink is never resolved through, on the way to a write —
// worked by hand rather than through an *os.Root: that package anchors one
// root per tree it writes and lets openat2's RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS
// enforce it, but the file tools address the whole filesystem by absolute path
// across five separate writable trees and a short list of exact device nodes,
// not one tree opened once, so there is no single root to anchor here. Walking
// the path component by component with Lstat is the same rule stated by hand:
// nothing along the way is allowed to be a symlink, existing or not, so
// nothing here is ever resolved through one to find out where it leads.
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
