package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPlugin(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestPluginsParseInOrder(t *testing.T) {
	cfg, err := loadPlugin(t, `
[[plugin]]
name    = "browser"
path    = "./plugins/browser"
command = "node"
args    = ["server.js"]

[[plugin]]
name    = "db"
path    = "./plugins/db"
command = "./db-server"
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Plugins) != 2 {
		t.Fatalf("got %d plugins, want 2", len(cfg.Plugins))
	}
	if cfg.Plugins[0].Name != "browser" || cfg.Plugins[1].Name != "db" {
		t.Errorf("plugins are out of file order: %+v", cfg.Plugins)
	}
	if len(cfg.Plugins[0].Args) != 1 || cfg.Plugins[0].Args[0] != "server.js" {
		t.Errorf("args = %v", cfg.Plugins[0].Args)
	}
	if cfg.Plugins[1].Args != nil {
		t.Errorf("a plugin with no args got %v", cfg.Plugins[1].Args)
	}
	if err := cfg.CheckPlugins(); err != nil {
		t.Errorf("a complete pair of plugins was refused: %v", err)
	}
}

// The name is the prefix of every tool the plugin advertises, so it cannot
// contain the separator and cannot be a shape a client will rewrite (F-D36).
func TestAPluginNameCannotContainTheSeparator(t *testing.T) {
	for _, bad := range []string{"my_browser", "Browser", "browser.v2", "9lives", "-lead", "brow ser"} {
		_, err := loadPlugin(t, "[[plugin]]\nname = \""+bad+"\"\n")
		if err == nil {
			t.Errorf("plugin name %q was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "<name>_<tool>") && !strings.Contains(err.Error(), "lowercase") {
			t.Errorf("the refusal of %q does not say what the rule is: %v", bad, err)
		}
	}
	for _, good := range []string{"browser", "db", "web-search", "a1"} {
		if _, err := loadPlugin(t, "[[plugin]]\nname = \""+good+"\"\n"); err != nil {
			t.Errorf("plugin name %q is reasonable and was refused: %v", good, err)
		}
	}
}

func TestAPluginNameHasRoomForItsTools(t *testing.T) {
	_, err := loadPlugin(t, "[[plugin]]\nname = \""+strings.Repeat("a", 40)+"\"\n")
	if err == nil {
		t.Fatal("a 40-character prefix was accepted")
	}
	if !strings.Contains(err.Error(), "64") {
		t.Errorf("the refusal does not name the limit it is protecting: %v", err)
	}
}

// The whole-file checks: what a single key cannot see.
func TestAnIncompletePluginIsRefusedBeforeAnythingIsPacked(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no name", "[[plugin]]\npath = \"./x\"\ncommand = \"node\"\n", "no name"},
		{"no path", "[[plugin]]\nname = \"x\"\ncommand = \"node\"\n", "no path"},
		{"no command", "[[plugin]]\nname = \"x\"\npath = \"./x\"\n", "no command"},
	} {
		cfg, err := loadPlugin(t, tc.body)
		if err != nil {
			t.Fatalf("%s: the file did not even parse: %v", tc.name, err)
		}
		err = cfg.CheckPlugins()
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the refusal does not say %q: %v", tc.name, tc.want, err)
		}
	}
}

// Two plugins with one name would advertise the same tools, and the agent could
// not tell them apart. The refusal names both lines.
func TestTwoPluginsCannotShareAName(t *testing.T) {
	cfg, err := loadPlugin(t, `
[[plugin]]
name    = "browser"
path    = "./a"
command = "node"

[[plugin]]
name    = "browser"
path    = "./b"
command = "node"
`)
	if err != nil {
		t.Fatal(err)
	}
	err = cfg.CheckPlugins()
	if err == nil {
		t.Fatal("two plugins named browser were accepted")
	}
	if !strings.Contains(err.Error(), "first declared at line") {
		t.Errorf("the refusal does not point at the other one: %v", err)
	}
}

// There is no [[plugin]] allow, and asking for one is asking for a second door
// in a wall whose whole value is having one (docs/mcp-surface.md §3.1).
func TestAPluginCannotAskForEgress(t *testing.T) {
	_, err := loadPlugin(t, "[[plugin]]\nname = \"x\"\nallow = [\"example.com\"]\n")
	if err == nil {
		t.Fatal("a plugin was granted its own allowlist")
	}
	if !strings.Contains(err.Error(), "allow") {
		t.Errorf("the refusal does not name the key: %v", err)
	}
}
