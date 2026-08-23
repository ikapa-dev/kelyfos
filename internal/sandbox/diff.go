package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// What changed in a workspace while the sandbox had it (E5-2, docs/qol.md §2).
//
// The comparison is against a manifest written when the workspace was packed,
// not against the host directory as it is now: the host directory may have been
// edited while the sandbox ran, and "what did the agent do" and "what has
// changed since I looked" are different questions. The second one is what
// SyncBack's fingerprint already answers.

// manifestSchema is the version of the format below. It travels with the file
// so a manifest written by an older kelyfos can be recognised rather than
// misread.
const manifestSchema = 1

// diffLineLimit bounds the line-by-line comparison. Above it the change is
// still reported, as a byte delta, and says which it is — an honest coarse
// answer beats an exact one that takes a minute on a file nobody reads.
const diffLineLimit = 5000

// Entry is one path as it was when the workspace was packed.
type Entry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Dir  bool   `json:"dir,omitempty"`
	Link string `json:"link,omitempty"`
	Size int64  `json:"size,omitempty"`
	// SHA256 is of the file's contents. Deliberately not Fingerprint's digest,
	// which mixes in modification times: that answers "did this change under
	// me" and this answers "is this the same file" (F-D45).
	SHA256 string `json:"sha256,omitempty"`
}

// WorkspaceManifest is what a pack recorded. Named for the workspace because
// the image manifest (image.json) is a different thing with the same word.
type WorkspaceManifest struct {
	Schema  int     `json:"schema"`
	Packed  string  `json:"packed"`
	Root    string  `json:"root"`
	Entries []Entry `json:"entries"`
}

// Change is one difference between the manifest and what came back.
type Change struct {
	Path string
	// Kind is 'A', 'M' or 'D'.
	Kind byte
	// Added and Removed are lines, for a file that is text at both ends.
	Added, Removed int
	// Bytes is the size delta, which is what a binary file reports instead.
	Bytes int64
	// Mode is set when only the mode changed, or changed as well.
	Mode string
	// Binary says the counts above are bytes rather than lines.
	Binary bool
}

func manifestPath(imagePath string) string { return imagePath + ".manifest.json" }

// writeWorkspaceManifest records a packed directory beside its image.
func writeWorkspaceManifest(hostDir, imagePath, packedAt string) error {
	entries, err := scanTree(hostDir)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(WorkspaceManifest{
		Schema: manifestSchema, Packed: packedAt, Root: hostDir, Entries: entries,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath(imagePath), append(blob, '\n'), 0o600)
}

// ReadManifest loads what a pack recorded, or reports that there is none —
// which is the case for an image packed by an older kelyfos, and is a fact a
// caller has to be able to tell apart from "nothing changed".
func ReadWorkspaceManifest(imagePath string) (*WorkspaceManifest, error) {
	blob, err := os.ReadFile(manifestPath(imagePath))
	if err != nil {
		return nil, err
	}
	var m WorkspaceManifest
	if err := json.Unmarshal(blob, &m); err != nil {
		return nil, fmt.Errorf("the workspace manifest is unreadable: %w", err)
	}
	if m.Schema != manifestSchema {
		return nil, fmt.Errorf("the workspace manifest is schema %d and this kelyfos writes %d",
			m.Schema, manifestSchema)
	}
	return &m, nil
}

// scanTree records a directory the way the manifest describes it.
func scanTree(root string) ([]Entry, error) {
	var out []Entry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		// An ext4 artefact, not anybody's content — and it appears only on one
		// side, so leaving it in would report a deletion nobody made.
		if rel == "lost+found" {
			return fs.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return nil // vanished mid-walk; it will read as deleted, which it is
		}
		e := Entry{Path: filepath.ToSlash(rel), Mode: fmt.Sprintf("%04o", info.Mode().Perm())}
		switch {
		case d.IsDir():
			e.Dir = true
		case info.Mode()&fs.ModeSymlink != 0:
			e.Link, _ = os.Readlink(path)
		case info.Mode().IsRegular():
			e.Size = info.Size()
			sum, err := fileDigest(path)
			if err != nil {
				return err
			}
			e.SHA256 = sum
		default:
			// Sockets and device nodes are not packed, so they are not recorded:
			// an entry only one side can ever have would read as a deletion.
			return nil
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func fileDigest(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// CompareTree is what the manifest says against what came back.
func CompareTree(m *WorkspaceManifest, tree string) ([]Change, error) {
	now, err := scanTree(tree)
	if err != nil {
		return nil, err
	}
	was := map[string]Entry{}
	for _, e := range m.Entries {
		was[e.Path] = e
	}
	seen := map[string]bool{}

	var out []Change
	for _, e := range now {
		seen[e.Path] = true
		old, existed := was[e.Path]
		switch {
		case !existed:
			c := Change{Path: e.Path, Kind: 'A'}
			if !e.Dir {
				c.Added, c.Bytes, c.Binary = countLines(filepath.Join(tree, e.Path))
			}
			out = append(out, c)
		case e.Dir || old.Dir:
			if e.Mode != old.Mode {
				out = append(out, Change{Path: e.Path, Kind: 'M', Mode: old.Mode + " → " + e.Mode})
			}
		case e.SHA256 != old.SHA256:
			c := Change{Path: e.Path, Kind: 'M', Bytes: e.Size - old.Size}
			if e.Mode != old.Mode {
				c.Mode = old.Mode + " → " + e.Mode
			}
			c.Added, c.Removed, c.Binary = diffCounts(filepath.Join(tree, e.Path), old, e)
			out = append(out, c)
		case e.Mode != old.Mode:
			// Identical contents and a different mode is still a change,
			// because it is one.
			out = append(out, Change{Path: e.Path, Kind: 'M', Mode: old.Mode + " → " + e.Mode})
		}
	}
	for _, e := range m.Entries {
		if !seen[e.Path] {
			c := Change{Path: e.Path, Kind: 'D', Bytes: -e.Size}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// countLines is the added-lines figure for a file that is new. A file that is
// not text reports its size instead and says so.
func countLines(path string) (lines int, size int64, binary bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	if !isText(b) {
		return 0, int64(len(b)), true
	}
	return len(splitLines(b)), int64(len(b)), false
}

// diffCounts is the +/− for a file that changed. The old contents are not on
// disk any more — the manifest holds a digest, not the bytes — so this compares
// what came back against what the *host directory* still has, which for an
// unmodified host is the file as it was packed. Where the host copy is gone the
// counts fall back to the byte delta, which is said rather than guessed.
func diffCounts(nowPath string, old, current Entry) (added, removed int, binary bool) {
	nowBytes, err := os.ReadFile(nowPath)
	if err != nil {
		return 0, 0, true
	}
	oldPath := filepath.Join(oldRoot, old.Path)
	oldBytes, err := os.ReadFile(oldPath)
	if err != nil || !isText(nowBytes) || !isText(oldBytes) {
		return 0, 0, true
	}
	a, b := splitLines(oldBytes), splitLines(nowBytes)
	if len(a) > diffLineLimit || len(b) > diffLineLimit {
		return 0, 0, true
	}
	common := lcs(a, b)
	return len(b) - common, len(a) - common, false
}

// oldRoot is where diffCounts looks for the pre-run copy of a file. It is set
// for the duration of one comparison rather than threaded through, because the
// alternative is a parameter on a function whose only caller already knows it.
var oldRoot string

func isText(b []byte) bool {
	if bytes.IndexByte(b, 0) >= 0 {
		return false
	}
	return len(b) < 8<<20
}

func splitLines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// lcs is the length of the longest common subsequence, which is all numstat
// needs: added is len(b) − common and removed is len(a) − common. Two rolling
// rows rather than a full table, so the memory is the width of one file.
func lcs(a, b []string) int {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			if a[i-1] == b[j-1] {
				cur[j] = prev[j-1] + 1
			} else if prev[j] >= cur[j-1] {
				cur[j] = prev[j]
			} else {
				cur[j] = cur[j-1]
			}
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// FormatChanges renders a comparison the way `git diff --numstat` reads,
// because that is the shape people already know.
// signed writes a byte delta with the same minus sign the line counts use.
// Two glyphs in one column — an ASCII hyphen for bytes and U+2212 for lines —
// is the kind of thing nobody reports and everybody notices (found by the E5
// exit exam).
func signed(n int64) string {
	if n < 0 {
		return "−" + strconv.FormatInt(-n, 10)
	}
	return "+" + strconv.FormatInt(n, 10)
}

func FormatChanges(changes []Change) string {
	if len(changes) == 0 {
		return "  no changes\n"
	}
	width := 0
	for _, c := range changes {
		if len(c.Path) > width {
			width = len(c.Path)
		}
	}
	if width > 60 {
		width = 60
	}
	var b strings.Builder
	for _, c := range changes {
		detail := ""
		switch {
		case c.Binary && c.Bytes != 0:
			detail = signed(c.Bytes) + " bytes"
		case c.Binary:
			detail = "binary"
		case c.Added > 0 && c.Removed > 0:
			detail = fmt.Sprintf("+%d −%d", c.Added, c.Removed)
		case c.Added > 0:
			detail = fmt.Sprintf("+%d", c.Added)
		case c.Removed > 0:
			detail = fmt.Sprintf("−%d", c.Removed)
		case c.Bytes != 0:
			detail = signed(c.Bytes) + " bytes"
		}
		if c.Mode != "" {
			if detail != "" {
				detail += " · "
			}
			detail += "mode " + c.Mode
		}
		fmt.Fprintf(&b, " %c %-*s  %s\n", c.Kind, width, c.Path, detail)
	}
	return b.String()
}

// Counts summarises a comparison for a one-line answer and for the record.
func Counts(changes []Change) (added, modified, deleted int) {
	for _, c := range changes {
		switch c.Kind {
		case 'A':
			added++
		case 'M':
			modified++
		case 'D':
			deleted++
		}
	}
	return added, modified, deleted
}
