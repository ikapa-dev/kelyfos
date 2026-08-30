package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
)

// P7-17/F21, the second half (owner's ruling of 2026-08-29): a `[[plugin]]`
// path outside the policy file's own tree is refused unless the same value is
// typed on the command line, which is exactly the rule `--workspace` already
// gets. `--plugin-path` is the flag that makes the hatch exist, and its absence
// was why this half was stopped the first time round.
//
// The path matters because of what it does: the directory is packed into a
// read-only device and mounted in the guest, so everything in it becomes
// readable by whatever the agent runs. A `kelyfos.toml` naming
// `plugin.path = "/home/you/.ssh"` hands the agent a key.

func pluginCfg(t *testing.T, dir string, paths ...string) *config.Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("[sandbox]\nimage = \"dev\"\n")
	for i, p := range paths {
		b.WriteString("\n[[plugin]]\n")
		b.WriteString("name = \"p" + string(rune('a'+i)) + "\"\n")
		b.WriteString("path = \"" + p + "\"\n")
		b.WriteString("command = \"./server\"\n")
	}
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestF21_APluginPathOutsideThePolicysTreeIsRefused(t *testing.T) {
	project := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "plug"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Inside the tree: allowed with no flag at all.
	if err := checkPluginScope(pluginCfg(t, project, "./plug"), nil); err != nil {
		t.Errorf("a plugin inside the project was refused: %v", err)
	}

	// Outside it: refused, and the refusal names the flag and the path.
	cfg := pluginCfg(t, project, elsewhere)
	err := checkPluginScope(cfg, nil)
	if err == nil {
		t.Fatalf("a plugin path at %s, outside %s, was accepted", elsewhere, project)
	}
	if !strings.Contains(err.Error(), "--plugin-path") {
		t.Errorf("the refusal does not name the escape hatch: %v", err)
	}
	if !strings.Contains(err.Error(), elsewhere) {
		t.Errorf("the refusal does not name the path: %v", err)
	}

	// Typed on the command line: allowed, because it is then the operator's
	// decision rather than the file's.
	if err := checkPluginScope(cfg, []string{elsewhere}); err != nil {
		t.Errorf("a plugin path named with --plugin-path was still refused: %v", err)
	}
	// A relative form of the same directory counts as the same directory.
	if err := checkPluginScope(cfg, []string{elsewhere + "/."}); err != nil {
		t.Errorf("--plugin-path did not match the same directory written differently: %v", err)
	}
	// Naming a DIFFERENT directory does not unlock this one.
	if err := checkPluginScope(cfg, []string{filepath.Join(elsewhere, "nope")}); err == nil {
		t.Error("--plugin-path naming another directory unlocked this one")
	}
}

// Every out-of-tree plugin has to be named, not just one of them: a file with
// two of them and one flag is still asking for something the operator did not
// agree to.
func TestF21_EveryOutOfTreePluginMustBeNamed(t *testing.T) {
	project := t.TempDir()
	a, b := t.TempDir(), t.TempDir()
	cfg := pluginCfg(t, project, a, b)

	if err := checkPluginScope(cfg, []string{a}); err == nil {
		t.Error("naming one of two out-of-tree plugin paths was enough")
	} else if !strings.Contains(err.Error(), b) {
		t.Errorf("the refusal does not name the one that is still unapproved: %v", err)
	}
	if err := checkPluginScope(cfg, []string{a, b}); err != nil {
		t.Errorf("naming both was still refused: %v", err)
	}
}

// A symlink inside the project pointing out of it is the way a lexical check is
// walked around — the same lesson F18 taught the workspace extractor a layer
// down, and the same resolution the workspace rule already does.
func TestF21_ASymlinkOutOfTheTreeDoesNotGetAPluginIn(t *testing.T) {
	project := t.TempDir()
	elsewhere := t.TempDir()
	link := filepath.Join(project, "plug")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("symlinks are not available here: %v", err)
	}
	if err := checkPluginScope(pluginCfg(t, project, "./plug"), nil); err == nil {
		t.Error("a symlink inside the project pointing out of it was accepted")
	}
}

// And a policy with no plugins at all is not something to have an opinion
// about.
func TestF21_APolicyWithNoPluginsIsUnaffected(t *testing.T) {
	if err := checkPluginScope(pluginCfg(t, t.TempDir()), nil); err != nil {
		t.Errorf("a policy declaring no plugins was refused: %v", err)
	}
	if err := checkPluginScope(nil, nil); err != nil {
		t.Errorf("no policy at all was refused: %v", err)
	}
}
