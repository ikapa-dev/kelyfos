package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
)

// The hostile corpus for the workspace block device (P6-22).
//
// This is the surface §5's trust-boundary table did not list. The guest holds a
// virtio-blk disk, writes a filesystem onto it, and the host reads that
// filesystem back with debugfs when the sandbox stops. Everything in the image
// — every name, every mode — is chosen by the untrusted side.
//
// These tests fail until P6-24. That is deliberate and it is the rule the
// corpus exists to enforce: a fixture is a failing test before it is a fixed
// one, because a fixture added after its fix is one nobody has watched fail.

// needsImageTools skips when mke2fs and debugfs are absent — unless the
// environment says they are required, which is what CI says. A hostile-input
// job that passes by running nothing is worse than no job at all: it reports a
// boundary as tested when nothing touched it.
func needsImageTools(t *testing.T) {
	t.Helper()
	var missing []string
	for _, tool := range []string{"mke2fs", "debugfs"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) == 0 {
		return
	}
	if os.Getenv("KELYFOS_HOSTILE") == "required" {
		t.Fatalf("KELYFOS_HOSTILE=required and %s missing: the hostile corpus did not run",
			strings.Join(missing, ", "))
	}
	t.Skipf("%s not installed", strings.Join(missing, ", "))
}

// C-1. A directory entry the guest authored decides where the host writes.
//
// This is the critical finding, and it is not a subtle one: the host runs
// `debugfs -R "rdump / <tree>"` over an image whose every byte the guest chose,
// and debugfs joins the names it finds to the destination. A name of `../../x`
// therefore lands two directories above the tree — outside the workspace,
// outside the run directory, anywhere the invoking user can write.
func TestHostileDirentCannotEscapeTheExtractionTree(t *testing.T) {
	needsImageTools(t)

	for _, name := range EscapingNames() {
		t.Run(name.Key, func(t *testing.T) {
			root := t.TempDir()
			// A canary one level above the host directory. Nothing the
			// extraction does may reach it.
			canary := filepath.Join(root, "OUTSIDE")
			if err := os.WriteFile(canary, []byte("the host's own file\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			hostDir := filepath.Join(root, "deep", "work")
			if err := os.MkdirAll(hostDir, 0o755); err != nil {
				t.Fatal(err)
			}
			img := filepath.Join(root, "ws.ext4")
			if err := BuildHostileImage(img, name, "written by the guest\n"); err != nil {
				t.Fatal(err)
			}

			w := HostileWorkspace(hostDir, img)
			s, err := w.Stage()
			if err == nil {
				defer s.Discard()
			}

			// Either outcome is acceptable on its own terms — refusing the
			// image, or extracting it with the name neutralised — and exactly
			// one thing is not: a byte outside the tree.
			problem := ""
			if escaped := escapees(t, root, filepath.Dir(hostDir)); len(escaped) > 0 {
				problem = fmt.Sprintf("%s: the entry %q wrote outside the extraction tree: %v",
					name.Why, name.Crafted, escaped)
			}
			if got, _ := os.ReadFile(canary); string(got) != "the host's own file\n" {
				problem = fmt.Sprintf("%s: a host file outside the workspace was overwritten", name.Why)
			}
			if err != nil {
				t.Logf("the image was refused, which is a correct answer: %v", err)
			}
			hostile.Holds(t, "dirent/"+name.Key, problem)
		})
	}
}

// escapees lists anything that appeared outside the directory the extraction was
// pointed at. The sync tree and the host directory itself are where output
// belongs; everything else is an escape.
func escapees(t *testing.T, root, allowedUnder string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == root {
			return nil //nolint:nilerr // a path that vanished is not an escape
		}
		if strings.HasPrefix(path, allowedUnder) {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == "OUTSIDE" || filepath.Base(path) == "ws.ext4" {
			return nil // placed by the test itself
		}
		out = append(out, strings.TrimPrefix(path, root+"/"))
		return nil
	})
	return out
}

// H-2. The dangerous half of a mode the guest chose must not reach the host.
//
// debugfs restores what the image says, so a guest that marks a file 0777 — or,
// worse, setuid — hands the host a file with those bits on. The host is not
// obliged to take permission advice from the thing it is sandboxing.
//
// The bits this asserts on are world-write and the special three, and not
// group-write, which the fix originally stripped too. That was caught by the
// acceptance suite rather than here: a user whose umask is 002 has a project of
// 0664 files, and stripping the bit rewrote every one of them on the way back.
// The fixture was widened to match a rule that was wrong, and narrowing it is
// part of the same correction.
func TestGuestChosenModesDoNotSurviveOntoTheHost(t *testing.T) {
	needsImageTools(t)

	for _, mode := range []os.FileMode{0o777, 0o666, os.ModeSetuid | 0o755} {
		t.Run(mode.String(), func(t *testing.T) {
			root := t.TempDir()
			hostDir := filepath.Join(root, "work")
			if err := os.MkdirAll(hostDir, 0o755); err != nil {
				t.Fatal(err)
			}
			img := filepath.Join(root, "ws.ext4")
			if err := BuildImageWithModes(img, mode); err != nil {
				t.Fatal(err)
			}

			w := HostileWorkspace(hostDir, img)
			s, err := w.Stage()
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			defer s.Discard()

			info, err := os.Stat(filepath.Join(s.tree, "wide-open"))
			if err != nil {
				t.Fatal(err)
			}
			got, problem := info.Mode(), ""
			if got&os.ModeSetuid != 0 {
				problem = fmt.Sprintf("a setuid bit the guest chose survived onto the host: %v", got)
			}
			if got.Perm()&0o002 != 0 {
				problem = fmt.Sprintf("the guest made a host file world-writable: %v", got.Perm())
			}
			hostile.Holds(t, "modes/"+mode.String(), problem)
		})
	}
}

// And the directory the workspace lands in keeps its own mode. The image's root
// carries whatever the guest gave it, and a swap that adopted it would let the
// guest reset the permissions of a directory on the host that it never owned.
func TestTheWorkspaceRootKeepsTheHostsMode(t *testing.T) {
	needsImageTools(t)

	root := t.TempDir()
	hostDir := filepath.Join(root, "work")
	if err := os.MkdirAll(hostDir, 0o750); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(hostDir)
	if err != nil {
		t.Fatal(err)
	}
	img := filepath.Join(root, "ws.ext4")
	if err := BuildImageWithModes(img, 0o644); err != nil {
		t.Fatal(err)
	}

	w := HostileWorkspace(hostDir, img)
	s, err := w.Stage()
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if _, _, err := s.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	after, err := os.Stat(hostDir)
	if err != nil {
		t.Fatal(err)
	}
	problem := ""
	if before.Mode().Perm() != after.Mode().Perm() {
		problem = fmt.Sprintf("the workspace root's mode changed from %v to %v — the guest chose the second one",
			before.Mode().Perm(), after.Mode().Perm())
	}
	hostile.Holds(t, "workspace-root-mode", problem)
}
