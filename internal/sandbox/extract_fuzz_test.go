package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzExtractImageLinks attacks the layer FuzzEntryFrom cannot see: not one
// manifest record but a whole staging tree of symlinks, resolved as a chain.
// The property under attack is the one the extraction's contract rests on —
// whatever validLinkChain ACCEPTS, the resolved landing is inside the
// workspace. A chain that escapes must be refused; a chain that is accepted
// and still lands outside is an escape with the extractor's signature on it.
//
// Each iteration builds a real staging tree (temp dir, real symlinks), so
// the walker reads the same kind of truth a sync-back would.
func FuzzExtractImageLinks(f *testing.F) {
	// Chains the review and the f9evasion corpus already taught us about.
	for _, seed := range [][]string{
		{"a:/etc/passwd"},
		{"a:../../etc/passwd"},
		{"sub/a:../..", "b:/sub/../.."},
		{"d1:x", "sub/d2:d1", "leak:sub/d2/../../.."},
		{"l1:l2", "l2:l3", "l3:/etc"},
		{"loop:loop"},
		{"self:./self"},
		{"deep:" + strings.Repeat("d/", 60) + "x"},
	} {
		var sb strings.Builder
		for _, s := range seed {
			sb.WriteString(s)
			sb.WriteString("\n")
		}
		f.Add(sb.String())
	}

	f.Fuzz(func(t *testing.T, spec string) {
		root := t.TempDir()
		// The spec is a newline-separated set of path:target links, each path
		// confined to a fixed set of slots so the tree stays buildable and the
		// fuzzing power goes into the TARGETS — the part that decides whether
		// a chain escapes.
		slots := []string{"a", "b", "c", "sub/a", "sub/b", "d1", "sub/d2", "leak", "loop", "self", "l1", "l2", "l3", "deep"}
		links := map[string]string{}
		for i, line := range strings.Split(spec, "\n") {
			if i >= len(slots) {
				break
			}
			path, target, _ := strings.Cut(line, ":")
			if path == "" || strings.ContainsAny(path, "/\\") {
				continue
			}
			target = strings.ReplaceAll(target, "\x00", "")
			slot := slots[i]
			if slot == "sub/a" || slot == "sub/b" || slot == "sub/d2" {
				_ = os.MkdirAll(filepath.Join(root, "sub"), 0o755)
			}
			if err := os.Symlink(target, filepath.Join(root, slot)); err != nil {
				continue
			}
			links[slot] = target
		}
		// A plain file so a chain can land on something real.
		_ = os.WriteFile(filepath.Join(root, "plain"), []byte("x"), 0o644)

		steps := 0
		w := newLinkWalker(root, &steps)
		for _, slot := range slots {
			if _, ok := links[slot]; !ok {
				continue
			}
			if err := validLinkChain(w, slot, w.readlink(slot)); err != nil {
				continue // refused: exactly what the extraction must do
			}
			// Accepted — so the chain must land inside the workspace. Resolve
			// it the way the kernel would and check where it really goes.
			// Landing on the workspace directory itself (a target of "." is
			// how) is inside, which the prefix test alone would reject.
			landing, err := filepath.EvalSymlinks(filepath.Join(root, slot))
			if err != nil {
				continue // dangling: nothing lands, nothing escapes
			}
			clean := filepath.Clean(root)
			if landing != clean && !strings.HasPrefix(landing, clean+string(os.PathSeparator)) {
				t.Fatalf("accepted chain for %q lands outside the workspace: %s", slot, landing)
			}
		}
	})
}
