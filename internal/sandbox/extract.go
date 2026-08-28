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
//  2. The extraction writes through an *os.Root. debugfs never chooses a
//     destination again: it dumps into staging files this package names, and the
//     guest's own names are only ever used through the root. So a name that
//     slips past the first layer still cannot reach outside the tree.
//
//     What os.Root is, since this comment twice said something it is not: it is
//     **not** openat2, and there is no RESOLVE_BENEATH or RESOLVE_NO_SYMLINKS
//     anywhere in it. Go 1.27 walks the path one component at a time with
//     openat(O_NOFOLLOW|O_CLOEXEC) and resolves each symlink itself, in
//     checkSymlink, restarting the walk against the link's contents; a resolved
//     path that would leave the root is refused at that point, with no window.
//     `openat2Trap` exists in the tree as a syscall number and is never called.
//
//     The guarantee, which is what actually matters here: a relative link that
//     stays inside the tree is followed, and everything else — a link that
//     climbs out, and *any* absolute link, even one pointing back inside — is
//     refused with "path escapes from parent". Asserted rather than believed, in
//     TestF18_ASymlinkChainCannotBeLeftInTheProject.
//
//     So it covers where the extraction *writes* and says nothing about what it
//     *leaves behind* for the next tool to follow — which is F18, and is why
//     validLinkChain exists.

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
	// size is what the inode says it holds, straight out of `ls -l -p`. It is
	// the only independent statement about a file the host has, and it is what
	// makes a short dump detectable: `debugfs dump` opens its destination
	// O_CREAT|O_TRUNC and copies block by block, reporting a per-command
	// failure on stderr and exiting 0 regardless, so a file that exists is not
	// evidence that a file came back (F17). Zero for a directory, where debugfs
	// leaves the field empty.
	size int64
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

// The echo listDirs attributes records by, and the two halves of it, kept
// together so the string that is written can only be read back by the string
// that matches it.
const (
	lsCommand = `ls -l -p "`
	lsEcho    = "debugfs: " + lsCommand
)

// listDirs runs one debugfs process over every directory at one level.
//
// debugfs echoes each command it reads from a script, which is what makes the
// output attributable: a block of records belongs to the directory named on the
// `debugfs: ls -l -p "<dir>"` line above it.
//
// The quotes are F4, and the whole of it. Unquoted, a directory name carrying
// whitespace lost everything inside it, two different ways, and said nothing:
//
//	`notes `     ls -l -p /notes      debugfs strips the trailing space while
//	                                  tokenising and reports "/notes: File not
//	                                  found by ext2_lookup"; the echo was then
//	                                  matched with TrimSpace, so the key became
//	                                  "/notes" and the directory was "/notes "
//	`my notes`   ls -l -p /my notes   two arguments: "Usage: ls [-c] [-d] [-l]
//	                                  [-p] [-r] file"
//
// Both leave blocks[dir] empty, the directory is created on the host with none
// of its contents, and debugfs exits 0 with the complaint on the stderr this
// used to discard. So the echo is matched with the quotes on — the key is the
// string that was submitted rather than a trimmed guess at it — and the
// attribution is cross-checked below, because neither of those messages is one
// anybody predicted and the next one will not be either.
//
// validName refuses both quote characters, which is what makes the quoting hold
// (S5c); everything else a name may contain, whitespace included, sits safely
// inside it.
func listDirs(imagePath string, dirs []string) (map[string][]string, error) {
	var script strings.Builder
	for _, d := range dirs {
		// A directory whose own name reached here has already been validated,
		// so it carries no newline to break the script and no quote to close
		// the argument early.
		fmt.Fprintf(&script, "%s%s\"\n", lsCommand, d)
	}
	out, stderr, err := runDebugfs(imagePath, script.String())
	if err != nil {
		return nil, fmt.Errorf("read the workspace image: %w: %s", err, strings.TrimSpace(stderr))
	}
	if bad := debugfsErrors(stderr); len(bad) > 0 {
		return nil, refuse("the image would not list its directories: %s", strings.Join(bad, "; "))
	}

	blocks := map[string][]string{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, lsEcho); ok {
			// A line that opens like an echo and does not close like one means
			// the parse has drifted, and the answer is to attribute nothing
			// rather than to attribute it to the wrong directory. The
			// cross-check below is what turns that into an error.
			current, _ = strings.CutSuffix(rest, `"`)
			continue
		}
		if current == "" || strings.TrimSpace(line) == "" {
			continue
		}
		blocks[current] = append(blocks[current], line)
	}

	// Every directory asked about has to have answered. debugfs echoes every
	// command it reads, and every directory holds at least `.` and `..`, so an
	// empty block is not an empty directory — it is a command that failed or an
	// attribution that drifted. A workspace that quietly comes back missing a
	// subtree is the failure mode this package refuses everywhere else.
	for _, d := range dirs {
		if len(blocks[d]) == 0 {
			return nil, refuse("the image lists nothing at all for %s, not even `.` and `..`; "+
				"its contents cannot be read and will not be guessed at", d)
		}
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
	// The size the inode records. debugfs prints a byte count for everything
	// but a directory, where the field is empty — verified against the real
	// tool, whose records read `/18/100664/501/1000/top.txt/4/` for a file and
	// `/16/040775/501/1000/plain//` for a directory.
	//
	// A file whose count does not parse is refused rather than defaulted,
	// because the count is the only thing the host has to check a dump against
	// and a defaulted one would check nothing (F17).
	if e.kind != kindDir {
		size, err := strconv.ParseInt(fields[6], 10, 64)
		if err != nil || size < 0 {
			return nil, refuse("%s records an unreadable size (%q), and the size is what says "+
				"whether what comes out of the image is the whole file",
				path.Join(dir, name), fields[6])
		}
		e.size = size
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
	case strings.ContainsAny(name, `"'`):
		// Neither character is a control character, so the loop below would
		// let both through — and dumpFiles interpolates this name inside a
		// double-quoted debugfs command. A double quote closes that quoted
		// argument early, handing debugfs's own tokenizer whatever follows as
		// unintended, unquoted tokens; a single quote is refused alongside it
		// because it is exactly as printable and exactly as unvetted for that
		// position, and there is no legitimate name that needs either badly
		// enough to carve out an exception (S5c).
		return refuse("%s contains a quote character, which cannot be closed safely inside the "+
			"double-quoted debugfs command dumpFiles builds for it", path.Join(dir, name))
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
//
// This is the per-link half. It cannot see a chain, because it is looking at one
// link with no idea what the others are — that is validLinkChain's job, and F18
// is what happens when only this half exists.
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

// A chain of links walks out of the workspace past a per-link check (F18).
//
// validLink judges each link alone and lexically, as though every other name in
// the tree were a real directory. Three links, none of which fails that
// question, compose into one that leaves:
//
//	sub/d1   -> ..              joins to "."          accepted
//	sub/d2   -> d1/..           joins to "sub"        accepted
//	sub/leak -> d2/etc/shadow   joins to "sub/d2/…"   accepted
//
// and really: sub/d1 is the tree, so sub/d1/.. is above it, so sub/leak points
// outside. The extraction cannot write through the chain — os.Root refuses a
// resolution that escapes — but the link is left in the person's directory for
// whatever follows it next: an editor, `tar -h`, `rsync -L`, or `kelyfos diff`'s
// own os.ReadFile on an added entry.
//
// The rule the review proposed first — refuse any target containing a ".."
// segment — is sound and is deliberately not what this does. `node_modules/x ->
// ../../packages/x` is what every pnpm and npm workspace looks like, and a
// refusal here refuses the *whole image*; on the resume path that is the
// person's session, because the workspace image is removed whether the
// write-back happened or not. The review's own second answer is the one taken:
// resolve the target through the entry set, which is the only lexical check
// that is also true, and refuse the links that actually leave.

// maxLinkHops bounds how far a chain is followed while it is being checked.
//
// **This number must stay above 40, and the inequality is the whole soundness
// argument — do not lower it to match the kernel and do not tidy it away.**
//
// Linux stops at 40 links in one path resolution. Sitting above that means every
// chain anything on this host could actually follow is resolved here to its end,
// so nothing is ever abandoned half-checked. That is what makes running out of
// budget **not** a refusal: the refusal is for leaving the tree, that is checked
// at every single step, and a resolution is deterministic — a walk that spent
// its whole budget without leaving has no second path it could have taken, and a
// chain long enough to exhaust this is ELOOP for every tool that meets it.
//
// Lower it below the kernel's limit and that inverts: a chain the kernel would
// happily follow all the way out of the workspace would be dropped unexamined
// and accepted.
//
// A cycle is contained by the same argument. It cannot be followed, by anybody,
// and refusing an image over one would cost somebody their session for a link
// that reaches nothing.
const maxLinkHops = 64

var (
	errLinkEscapes = errors.New("the link leaves the workspace")
	errLinkTooDeep = errors.New("the chain is longer than anything can follow")
)

// linkResolver answers, for one image, where a name inside the tree really
// lands once every symlink on the way has been followed.
//
// It holds the whole set, which is why the check that uses it runs after every
// target has been read rather than link by link during extraction.
type linkResolver struct {
	links map[string]string // entry path -> target, symlinks only
}

// walk resolves p starting from the directory cur — a list of components below
// the tree root — the way the kernel would.
func (r *linkResolver) walk(cur []string, p string, hops *int) ([]string, error) {
	if path.IsAbs(p) {
		// validLink refuses these before this ever runs. Answered anyway,
		// because the whole point of this layer is that the one above it will
		// one day be wrong: an absolute target is the host's root, which is not
		// inside the tree.
		return nil, errLinkEscapes
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			if len(cur) == 0 {
				return nil, errLinkEscapes
			}
			cur = cur[:len(cur)-1]
			continue
		}
		next := append(append([]string(nil), cur...), seg)
		target, isLink := r.links[strings.Join(next, "/")]
		if !isLink {
			// A file, a directory, or a name that is not in the image at all.
			// A dangling link is ordinary and is not this function's business.
			cur = next
			continue
		}
		*hops++
		if *hops > maxLinkHops {
			return cur, errLinkTooDeep
		}
		// A link is resolved from its own directory, which is where the walk
		// currently stands.
		resolved, err := r.walk(cur, target, hops)
		if err != nil {
			return nil, err
		}
		cur = resolved
	}
	return cur, nil
}

// validLinkChain refuses a symlink whose chain leaves the workspace.
func validLinkChain(r *linkResolver, from, target string) error {
	hops := 0
	// The link's own directory is resolved first: a component of it may itself
	// be a symlink, and the check has to start where the kernel would start.
	cur, err := r.walk(nil, path.Dir(from), &hops)
	if err == nil {
		_, err = r.walk(cur, target, &hops)
	}
	switch {
	case errors.Is(err, errLinkEscapes):
		return refuse("%s points at %s, which leaves the workspace once the links on the way are "+
			"followed; each link on its own looks like it stays", from, target)
	case errors.Is(err, errLinkTooDeep):
		return nil // see maxLinkHops: contained, and unfollowable by anything
	}
	return err
}

// extractImage writes the entries beneath root.
//
// Nothing here joins a guest-chosen name to a host path by hand. Directories and
// files are created through the root: a name that escaped the validation above
// still cannot escape it.
//
// This comment used to say the root was "openat2 with RESOLVE_BENEATH and
// RESOLVE_NO_SYMLINKS". It is neither — see the package comment for what os.Root
// actually does — and the two halves of that sentence contradicted each other,
// which is how a reader came away believing a planted symlink could not matter.
// What it does give: a link that stays inside the tree is **followed**, and one
// that leaves is refused at the open. That is the whole of F18 — the root stops
// the extraction writing *through* a chain, and says nothing about the chain
// being left behind for the next tool to follow.
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

	// Every symlink's target is read and checked before any of them is created,
	// and before a single file byte is written. A chain is only judgeable against
	// the whole set — the link that makes `sub/d2` climb may be enumerated after
	// the link that uses it — so there is no order in which a per-link check
	// could have been enough (F18).
	targets := map[string]string{}
	for _, e := range sorted {
		if e.kind != kindSymlink {
			continue
		}
		target, err := readLink(imagePath, e, staged[e.path])
		if err != nil {
			return err
		}
		if err := validLink(e.path, target); err != nil {
			return err
		}
		targets[e.path] = target
	}
	resolver := &linkResolver{links: targets}
	for _, e := range sorted {
		if e.kind != kindSymlink {
			continue
		}
		if err := validLinkChain(resolver, e.path, targets[e.path]); err != nil {
			return err
		}
	}

	for _, e := range sorted {
		switch e.kind {
		case kindFile:
			if err := copyThrough(root, e, staged[e.path]); err != nil {
				return err
			}
		case kindSymlink:
			if err := root.Symlink(targets[e.path], e.path); err != nil && !os.IsExist(err) {
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

// stagingRoot is the directory a dump lands in before anything is put in the
// person's tree.
//
// Under Root() rather than os.TempDir(), and that is a correctness choice
// rather than a tidiness one. On most Linux hosts /tmp is a tmpfs — RAM — and
// the guest chooses how many bytes it asks the host to stage: `truncate -s 100G
// /work/000` is a sparse file inside the image that `dump` materialises as
// zeros. Staging it in RAM fills the host's memory and then fails with ENOSPC,
// at which point every remaining dump in the same script writes nothing and
// exits 0 (F17). Root() is the filesystem the images already live on, which is
// the disk the person chose for this tool.
//
// A quote character anywhere in the path is refused, because the destination is
// interpolated into a double-quoted debugfs argument below — the same rule
// validName applies to the guest's half of that command line, applied to the
// host's half. It is close to unreachable (it needs a `"` in $HOME or in
// KELYFOS_CACHE) and it is one line.
func stagingRoot() (string, error) {
	dir := filepath.Join(Root(), "extract")
	if strings.ContainsAny(dir, `"'`) {
		return "", fmt.Errorf("the staging directory %s contains a quote character, which cannot be "+
			"closed safely inside the debugfs command that writes into it; set KELYFOS_CACHE "+
			"to a path without one", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// debugfsErrors picks debugfs's own per-command failures out of its stderr.
//
// This is the stream both callers used to discard, and discarding it is what
// made a per-command failure invisible: debugfs reports one through com_err —
// "<command>: <message>", so the prefix is the name of the command that failed
// — and then carries straight on to the next command and exits 0. Only a
// whole-process failure ever reached the caller.
//
// Matched on the prefix rather than anywhere in the line, which is a deliberate
// narrowing of what the review asked for. com_err always writes the name first,
// and a workspace is allowed to contain a file called `dump:notes`; refusing on
// the substring would refuse that person's whole image, and a refusal on this
// path costs them the session's work.
//
// The version banner debugfs prints at startup ("debugfs 1.47.0 (5-Feb-2023)")
// is not one of these — no colon after the name — and is not a failure.
func debugfsErrors(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		for _, prefix := range []string{"dump: ", "ls: ", "stat: ", "debugfs: "} {
			if strings.HasPrefix(line, prefix) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}

// runDebugfs runs one script over an image and hands back both streams.
//
// Separately, because they say different things: the records are on stdout and
// the failures are on stderr, and the previous CombinedOutput mixed them into
// one blob that nothing parsed.
func runDebugfs(imagePath, script string) (stdout, stderr string, err error) {
	f, err := os.CreateTemp("", "kelyfos-debugfs-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return "", "", err
	}
	if err := f.Close(); err != nil {
		return "", "", err
	}
	var outBuf, errBuf strings.Builder
	cmd := exec.Command("debugfs", "-f", f.Name(), imagePath)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// dumpFiles pulls every file's contents out of the image.
//
// The destinations are numbered by this package. That is the point of the whole
// arrangement: debugfs is given no guest-chosen name to write to, so the worst a
// crafted entry can do here is name a file that does not exist.
//
// Two invocations rather than one, and the split is not cosmetic. A *fast*
// symlink — one whose target is short enough to live inside the inode — has no
// data block, so `dump` on it legitimately writes nothing and legitimately
// prints `dump: Attempt to read block from filesystem resulted in short read`.
// Measured, against a five-character link:
//
//	/15/120777/501/1000/short/5/     ← the record
//	dump -p "/short" …/15            → 0 bytes, exit 0, that line on stderr
//
// readLink already expects this and falls back to `stat`. So treating stderr as
// fatal across one combined script would refuse every workspace containing a
// short symlink, which is most of them — the fix would cost more work than the
// defect. Regular files are dumped in their own process, where a line on stderr
// means exactly what it says.
func dumpFiles(imagePath string, entries []imageEntry) (map[string]string, func(), error) {
	root, err := stagingRoot()
	if err != nil {
		return nil, func() {}, err
	}
	dir, err := os.MkdirTemp(root, "kelyfos-extract-")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	staged := map[string]string{}
	var files, links strings.Builder
	var total int64
	for i, e := range entries {
		if e.kind == kindDir {
			continue
		}
		dest := filepath.Join(dir, strconv.Itoa(i))
		staged[e.path] = dest
		// The path inside the image is quoted for debugfs's own tokenizer. It
		// has been validated already — no newline, no control character, and
		// (S5c) no quote of either kind, which is what makes this quoting
		// actually hold: a quote character is ordinary and printable, not
		// whitespace and not a control character, and it is the one thing
		// that could close this quoted argument early. With it refused,
		// everything that can still appear — including whitespace — sits
		// safely inside this quoting.
		//
		// The destination is quoted for the same reason and was not: debugfs
		// splits its command line on whitespace, so a staging path containing a
		// space produced `dump: Usage: dump_inode [-p] <file> <output_file>`
		// and no dump at all, for every file in the image.
		line := fmt.Sprintf("dump -p \"/%s\" \"%s\"\n", e.path, dest)
		if e.kind == kindSymlink {
			links.WriteString(line)
			continue
		}
		files.WriteString(line)
		total += e.size
	}

	// Before a byte is written rather than after the disk is full. checkFreeSpace
	// says nothing when it cannot tell, which is the right silence: an
	// unanswerable statfs is not evidence of a full disk, and the size check in
	// copyThrough catches the case this misses anyway.
	if err := checkFreeSpace(dir, total); err != nil {
		cleanup()
		return nil, func() {}, fmt.Errorf("stage the workspace image: %w", err)
	}

	for _, pass := range []struct {
		script      string
		stderrFatal bool
	}{
		{files.String(), true},
		{links.String(), false},
	} {
		if pass.script == "" {
			continue
		}
		_, stderr, err := runDebugfs(imagePath, pass.script)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("read the workspace image: %w: %s",
				err, strings.TrimSpace(stderr))
		}
		if pass.stderrFatal {
			if bad := debugfsErrors(stderr); len(bad) > 0 {
				cleanup()
				return nil, func() {}, refuse("the image did not give up its contents: %s",
					strings.Join(bad, "; "))
			}
		}
	}
	return staged, cleanup, nil
}

func copyThrough(root *os.Root, e imageEntry, from string) error {
	if from == "" {
		return fmt.Errorf("%s was not extracted from the image", e.path)
	}
	// The size the record carries, against the size that came out. This is the
	// check that makes a partial dump structural rather than a matter of
	// noticing a message: `debugfs dump` opens its destination O_CREAT|O_TRUNC
	// and copies block by block, so a read error or an ENOSPC part way through
	// leaves a file that *exists* and is short — and "nothing staged", which was
	// the whole per-file check, is satisfied by it. What used to happen next was
	// that copyThrough installed it and Commit renamed the tree over the
	// project, with "workspace written back" printed underneath (F17).
	//
	// The whole extraction is refused rather than the one file, because a dump
	// that failed once has no reason to have succeeded for the entries after it
	// — the ENOSPC case fails every one of them — and because the person's own
	// copy is worth more than a partial write-back of the sandbox's.
	info, err := os.Stat(from)
	if err != nil {
		// A file debugfs could not read is a hole in the record of what came
		// back, and a workspace missing a file without saying so is worse than
		// one that refuses.
		return fmt.Errorf("read %s out of the workspace image: %w", e.path, err)
	}
	if info.Size() != e.size {
		return refuse("%s came out of the image as %d bytes and its record says it holds %d; "+
			"the dump did not finish, so nothing from this image is written back",
			e.path, info.Size(), e.size)
	}
	src, err := os.Open(from)
	if err != nil {
		return fmt.Errorf("read %s out of the workspace image: %w", e.path, err)
	}
	defer src.Close()

	dst, err := root.OpenFile(e.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, extractMode(e.mode, false))
	if err != nil {
		return fmt.Errorf("write %s into the workspace: %w", e.path, err)
	}
	n, err := io.Copy(dst, src)
	if err != nil {
		dst.Close()
		return fmt.Errorf("write %s into the workspace: %w", e.path, err)
	}
	if err := dst.Close(); err != nil {
		return err
	}
	// And what actually landed, which is the statement the person's disk cares
	// about. The Stat above is about the staged copy; this is about theirs.
	if n != e.size {
		return refuse("%d bytes of %s reached the workspace and its record says it holds %d",
			n, e.path, e.size)
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
