package sandbox

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Reading a filesystem the guest wrote (P6-24, findings C-1 and H-2).
//
// The workspace is a block device the guest holds. It writes the filesystem;
// the host reads it back when the sandbox stops. Every byte of it — every name,
// every mode, every symlink target — is chosen by the untrusted side, and §5's
// trust-boundary table did not list this surface at all.
//
// What it used to do was hand the whole job to one command:
//
//	debugfs -R "rdump / <tree>" <image>
//
// rdump joins the names it finds to the destination, so a directory entry named
// `../../pwn.` put the guest's bytes two directories above the tree — outside
// the workspace, outside the run directory, anywhere the invoking user could
// write. That was reproduced with the exact command, and it is C-1.
//
// Two layers replace it, and the second exists because the first will one day be
// wrong:
//
//  1. The image is enumerated and every entry validated before anything is
//     written. An entry the host cannot safely use makes the whole image
//     refused, by name. Refused rather than sanitised: a name that has to be
//     repaired is a name somebody built to be repaired, and the repaired version
//     is a guess about what they meant.
//
//  2. The extraction writes through an *os.Root, which is openat2 with
//     RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS underneath. debugfs never chooses
//     a destination again: it dumps into staging files this package names, and
//     the guest's own names are only ever used through the root. So a name that
//     slips past the first layer still cannot reach outside the tree, and the
//     kernel is what says so rather than this code.

// maxImageEntries bounds what enumeration will hold in memory.
//
// The guest chooses how many files there are, so something has to. The number is
// far above any workspace a person would sync — a large node_modules is tens of
// thousands — and the refusal says the number rather than leaving a reader to
// discover it.
const maxImageEntries = 500_000

// entryKind is what an entry is. Anything else — a device node, a socket, a
// fifo — is refused: a guest asking the host to create one in somebody's project
// directory is not a case with a good answer.
type entryKind int

const (
	kindFile entryKind = iota
	kindDir
	kindSymlink
)

type imageEntry struct {
	path string // validated, slash-separated, relative to the image root
	mode os.FileMode
	kind entryKind
	link string // the target, for a symlink
}

// ErrHostileImage is returned for an image the host will not read.
//
// It is one error for every reason, because the answer is the same in each case
// and because a caller that wanted to tell them apart would be a caller deciding
// which hostile images are acceptable.
var ErrHostileImage = errors.New("the workspace image contains an entry this host will not use")

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrHostileImage, fmt.Sprintf(format, args...))
}

// listImage enumerates a workspace image and refuses anything it cannot use.
//
// It walks a directory level at a time, batching every directory at that level
// into one debugfs invocation, so the number of processes is the depth of the
// tree rather than the number of directories in it.
func listImage(imagePath string) ([]imageEntry, error) {
	var out []imageEntry
	level := []string{"/"}
	for depth := 0; len(level) > 0; depth++ {
		if depth > 128 {
			return nil, refuse("the directory tree is more than 128 deep")
		}
		blocks, err := listDirs(imagePath, level)
		if err != nil {
			return nil, err
		}
		var next []string
		for _, dir := range level {
			for _, rec := range blocks[dir] {
				e, err := entryFrom(dir, rec)
				if err != nil {
					return nil, err
				}
				if e == nil {
					continue // . .. lost+found
				}
				if len(out) >= maxImageEntries {
					return nil, refuse("more than %d entries; this host will not enumerate a larger image",
						maxImageEntries)
				}
				out = append(out, *e)
				if e.kind == kindDir {
					next = append(next, "/"+e.path)
				}
			}
		}
		level = next
	}
	return out, nil
}

// listDirs runs one debugfs process over every directory at one level.
//
// debugfs echoes each command it reads from a script, which is what makes the
// output attributable: a block of records belongs to the directory named on the
// `debugfs: ls -l -p <dir>` line above it.
func listDirs(imagePath string, dirs []string) (map[string][]string, error) {
	var script strings.Builder
	for _, d := range dirs {
		// A directory whose own name reached here has already been validated,
		// so it carries no newline to break the script.
		fmt.Fprintf(&script, "ls -l -p %s\n", d)
	}
	f, err := os.CreateTemp("", "kelyfos-ls-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script.String()); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	out, err := exec.Command("debugfs", "-f", f.Name(), imagePath).Output()
	if err != nil {
		return nil, fmt.Errorf("read the workspace image: %w", err)
	}

	blocks := map[string][]string{}
	current := ""
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "debugfs: ls -l -p "); ok {
			current = strings.TrimSpace(rest)
			continue
		}
		if current == "" || strings.TrimSpace(line) == "" {
			continue
		}
		blocks[current] = append(blocks[current], line)
	}
	return blocks, nil
}

// entryFrom parses one record, and the parsing is the first half of the
// validation.
//
// The format is /inode/mode/uid/gid/name/size/ — so a name carrying a `/`
// produces extra fields and a name carrying a newline splits the record across
// lines. Neither can be parsed, and neither is repaired. That is the shape of
// this whole function: the strictness is the check, rather than a check bolted
// beside a lenient parser.
func entryFrom(dir, record string) (*imageEntry, error) {
	fields := strings.Split(record, "/")
	if len(fields) != 8 || fields[0] != "" || fields[7] != "" {
		return nil, refuse("an entry in %s does not parse as a directory record (%q); "+
			"a name containing a slash or a newline looks exactly like this", dir, record)
	}
	name := fields[5]
	switch name {
	case ".", "..":
		return nil, nil
	case "":
		return nil, refuse("an entry in %s has no name", dir)
	}
	if dir == "/" && name == "lost+found" {
		return nil, nil // an ext4 artefact, not the user's content
	}
	if err := validName(dir, name); err != nil {
		return nil, err
	}

	raw, err := strconv.ParseUint(fields[2], 8, 32)
	if err != nil {
		return nil, refuse("an entry in %s has an unreadable mode (%q)", dir, fields[2])
	}
	e := &imageEntry{
		path: strings.TrimPrefix(path.Join(dir, name), "/"),
		mode: os.FileMode(raw & 0o7777),
	}
	switch raw & 0o170000 {
	case 0o040000:
		e.kind = kindDir
	case 0o100000:
		e.kind = kindFile
	case 0o120000:
		e.kind = kindSymlink
	default:
		return nil, refuse("%s is neither a file, a directory nor a symlink (mode %o); "+
			"a device node, a socket or a fifo is not something to create in somebody's project",
			path.Join(dir, name), raw)
	}
	return e, nil
}

// validName is the refusal list, and it is a list of shapes rather than of
// characters somebody thought of.
func validName(dir, name string) error {
	switch {
	case strings.Contains(name, "/"):
		return refuse("%s contains a separator inside a single entry", path.Join(dir, name))
	case strings.ContainsRune(name, 0):
		return refuse("an entry in %s contains a NUL, which ends a name in C and not in Go", dir)
	case name == "." || name == "..":
		return refuse("an entry in %s is named %q", dir, name)
	case len(name) > 255:
		return refuse("an entry in %s has a name longer than a filesystem allows (%d bytes)", dir, len(name))
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return refuse("%s contains a control character (%q)", path.Join(dir, name), strconv.QuoteRune(r))
		}
	}
	return nil
}

// safeMode is what a mode the guest chose becomes on the host.
//
// Three things never survive: setuid, setgid and the sticky bit, because
// os.FileMode.Perm() is the only thing consulted, and **world-write**, which is
// the one permission that hands a file to every account on the machine. That is
// the rule docs/threat-model.md states, and it is about the mode *the guest
// chose*: a bit the host's own filesystem put on a directory this extraction
// created is not the guest's and is not this function's to drop — see
// extractImage's last loop, which puts it back.
//
// Group-write is deliberately left alone, and the first version of this function
// did strip it. That was wrong in a way worth recording, because the acceptance
// suite caught it rather than a fixture: a user whose umask is 002 has a project
// full of 0664 files, the guest never touched them, and stripping the bit turned
// every one of them into 0644 — so `--review` reported files the sandbox had not
// touched as modified, and a sync-back quietly changed the permissions on
// somebody's own work. A boundary that rewrites the user's files to protect them
// from the user is not protecting anybody.
//
// The line is drawn where the danger is. World-write is reachable by any account
// on the host; group-write is ordinarily the user's own group, and it is a
// permission they already chose for themselves.
//
// **Owner-write used to be forced on, and that was the same defect one bit
// over.** This function returned p|0o600 for a file and p|0o700 for a directory,
// so a 0444 file came back 0644 and a 0555 directory came back 0755 — the
// comparison in diff.go then reported `mode 0444 → 0644` against a file the
// sandbox had never opened, and the sync-back renamed that tree into place, so
// the permission on somebody's own untouched file changed on their disk. A
// project with a generated file made deliberately unwritable, or a vendored tree
// checked in read-only, is an ordinary project. The bits are still forced while
// the extraction is running — see extractMode — because a file has to be written
// and a directory has to be written into; what changed is that they come back
// off when there is nothing left to write.
//
// What is still floored is owner-*read*, and owner-execute on a directory,
// because the host has to be able to read back what it just extracted: the
// comparison digests every file and walks every directory, and a guest that
// wrote a mode-0 file could otherwise stop `kelyfos diff` working at all. That
// floor cannot rewrite anything the person owns, and the reason is worth stating
// rather than trusting: packing writes the manifest by walking the tree and
// digesting every file, so an entry that came from the host already had u+r — or
// u+rx — or it could not have been packed in the first place. The floor only
// ever reaches a mode the guest invented.
func safeMode(m os.FileMode, dir bool) os.FileMode {
	p := m.Perm() &^ 0o002
	if dir {
		return p | 0o500
	}
	return p | 0o400
}

// extractMode is what an entry is created with while the extraction is still
// running: what it will end up as, plus the owner bits the host needs to finish
// writing it. safeMode goes back on once there is nothing left to write.
func extractMode(m os.FileMode, dir bool) os.FileMode {
	if dir {
		return safeMode(m, true) | 0o700
	}
	return safeMode(m, false) | 0o600
}

// validLink refuses a symlink target the guest should not be able to plant.
//
// A relative link inside the tree is ordinary and common — a project full of
// them is a normal project — and it is recreated. An absolute one, or one that
// climbs out, is the guest leaving something behind that reads a host file when
// the person whose directory this becomes later follows it. They did not put it
// there.
func validLink(from, target string) error {
	switch {
	case target == "":
		return refuse("%s is a symlink with no target", from)
	case strings.ContainsRune(target, 0):
		return refuse("%s is a symlink whose target contains a NUL", from)
	case path.IsAbs(target):
		return refuse("%s points at %s, which is a path on the host rather than inside the workspace",
			from, target)
	}
	// Where it lands, relative to the tree's root.
	landing := path.Join(path.Dir(from), target)
	if landing == ".." || strings.HasPrefix(landing, "../") {
		return refuse("%s points at %s, which is outside the workspace", from, target)
	}
	return nil
}

// extractImage writes the entries beneath root.
//
// Nothing here joins a guest-chosen name to a host path by hand. Directories and
// files are created through the root, which is openat2 with RESOLVE_BENEATH and
// RESOLVE_NO_SYMLINKS: a name that escaped the validation above still cannot
// escape the kernel, and a symlink planted earlier in the same extraction cannot
// be written through.
func extractImage(imagePath string, entries []imageEntry, root *os.Root) error {
	// Shallowest first, so a parent exists before anything inside it.
	sorted := append([]imageEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.Count(sorted[i].path, "/") < strings.Count(sorted[j].path, "/")
	})

	for _, e := range sorted {
		if e.kind != kindDir {
			continue
		}
		if err := root.Mkdir(e.path, extractMode(e.mode, true)); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create %s in the workspace: %w", e.path, err)
		}
	}

	staged, cleanup, err := dumpFiles(imagePath, sorted)
	if err != nil {
		return err
	}
	defer cleanup()

	for _, e := range sorted {
		switch e.kind {
		case kindFile:
			if err := copyThrough(root, e, staged[e.path]); err != nil {
				return err
			}
		case kindSymlink:
			target, err := readLink(imagePath, e, staged[e.path])
			if err != nil {
				return err
			}
			if err := validLink(e.path, target); err != nil {
				return err
			}
			if err := root.Symlink(target, e.path); err != nil && !os.IsExist(err) {
				return fmt.Errorf("create the symlink %s: %w", e.path, err)
			}
		}
	}

	// The directories' own modes go on last, and deepest first. Until every
	// entry inside a directory has been written the host needs to be able to
	// write into it, which is why it was created with the owner bits forced —
	// but a directory the person packed read-only has to come back read-only,
	// or the sync-back changes a permission on their disk that nothing touched.
	// sorted is shallowest-first, so walking it backwards is deepest-first.
	//
	// What the directory already carries is kept, and that is not a softening of
	// the rule above. chmod(2) sets the whole mode word, so a mode built from
	// Perm() clears S_ISGID — and setgid is exactly what a directory here is
	// likely to have arrived with, because the standard way a team keeps a
	// checkout group-owned is chmod g+s on the directory above it, and on Linux
	// the kernel then gives that bit to every directory created underneath. The
	// extraction tree is created beside the host directory, so under that same
	// parent, and Commit renames the tree into the project's place. Stripping it
	// there is silent twice over: diff.go's scanTree records Mode().Perm(), so
	// no comparison can report it, and what the person eventually sees is new
	// files landing in the wrong group. The bits put back can only be the host's
	// own — nothing this package
	// creates a directory with carries them, since safeMode and extractMode
	// consult Perm() and the guest's setgid is a low bit of e.mode that Perm()
	// drops before mkdir ever sees it.
	for i := len(sorted) - 1; i >= 0; i-- {
		e := sorted[i]
		if e.kind != kindDir {
			continue
		}
		mode := safeMode(e.mode, true)
		if info, err := root.Lstat(e.path); err == nil {
			mode |= info.Mode() & (os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		}
		if err := root.Chmod(e.path, mode); err != nil {
			return fmt.Errorf("set the mode of %s in the workspace: %w", e.path, err)
		}
	}
	return nil
}

// dumpFiles pulls every file's contents out in one debugfs process.
//
// The destinations are numbered by this package. That is the point of the whole
// arrangement: debugfs is given no guest-chosen name to write to, so the worst a
// crafted entry can do here is name a file that does not exist.
func dumpFiles(imagePath string, entries []imageEntry) (map[string]string, func(), error) {
	dir, err := os.MkdirTemp("", "kelyfos-extract-")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	staged := map[string]string{}
	var script strings.Builder
	for i, e := range entries {
		if e.kind == kindDir {
			continue
		}
		dest := filepath.Join(dir, strconv.Itoa(i))
		staged[e.path] = dest
		// The path inside the image is quoted for debugfs's own tokenizer. It
		// has been validated already — no newline, no control character — so
		// what is left is whitespace, which quoting covers.
		fmt.Fprintf(&script, "dump -p \"/%s\" %s\n", e.path, dest)
	}
	if script.Len() == 0 {
		return staged, cleanup, nil
	}

	f, err := os.CreateTemp("", "kelyfos-dump-*")
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script.String()); err != nil {
		f.Close()
		cleanup()
		return nil, func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	// debugfs reports a failure per command on stderr and still exits 0, so the
	// per-file check is the copy below finding nothing staged. A whole-process
	// failure is what this catches.
	if out, err := exec.Command("debugfs", "-f", f.Name(), imagePath).CombinedOutput(); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("read the workspace image: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return staged, cleanup, nil
}

func copyThrough(root *os.Root, e imageEntry, from string) error {
	if from == "" {
		return fmt.Errorf("%s was not extracted from the image", e.path)
	}
	src, err := os.Open(from)
	if err != nil {
		// A file debugfs could not read is a hole in the record of what came
		// back, and a workspace missing a file without saying so is worse than
		// one that refuses.
		return fmt.Errorf("read %s out of the workspace image: %w", e.path, err)
	}
	defer src.Close()

	dst, err := root.OpenFile(e.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, extractMode(e.mode, false))
	if err != nil {
		return fmt.Errorf("write %s into the workspace: %w", e.path, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return fmt.Errorf("write %s into the workspace: %w", e.path, err)
	}
	if err := dst.Close(); err != nil {
		return err
	}
	// O_CREATE's mode is masked by umask, and the executable bit is the half of
	// the guest's intent worth keeping. What goes on here is the final mode
	// rather than the one the write needed: the copy is finished, so owner-write
	// is no longer anybody's business but the person whose file this becomes.
	return root.Chmod(e.path, safeMode(e.mode, false))
}

// readLink recovers a symlink's target.
//
// ext4 keeps a short target inside the inode and a long one in a data block, and
// debugfs reports them differently: `stat` prints a fast link's destination and
// `dump` reads a slow one. Both are tried, because refusing a project's symlinks
// for being long would be a regression dressed as a defence.
func readLink(imagePath string, e imageEntry, staged string) (string, error) {
	if staged != "" {
		if b, err := os.ReadFile(staged); err == nil && len(b) > 0 {
			return string(b), nil
		}
	}
	out, err := exec.Command("debugfs", "-R", "stat \"/"+e.path+"\"", imagePath).Output()
	if err != nil {
		return "", fmt.Errorf("read the symlink %s: %w", e.path, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Fast link dest: "); ok {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", refuse("%s is a symlink whose target this host could not read", e.path)
}
