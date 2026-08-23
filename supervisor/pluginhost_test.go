package main

import (
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/mcp"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
)

// The namespacing rule is the one thing here a test can check without a
// machine, and it is the part that would fail silently: a name something
// downstream rewrites still works, right up until two of them collide.

func TestANamespacedToolMustSurviveEveryClient(t *testing.T) {
	for _, ok := range []string{"browser_navigate", "db_query", "a_b-c", "x_" + strings.Repeat("t", 60)} {
		if !pluginToolName.MatchString(ok) {
			t.Errorf("%q is a name every client accepts and was refused", ok)
		}
	}
	for _, bad := range []string{
		"browser_nav.igate",                  // legal in MCP, rejected by the Messages API
		"browser_" + strings.Repeat("t", 60), // 68 characters, over the 64 limit
		"browser navigate",                   // a space
		"",                                   // nothing
	} {
		if pluginToolName.MatchString(bad) {
			t.Errorf("%q would be rewritten or rejected downstream and was accepted", bad)
		}
	}
}

// A plugin's tools are found by matching the declared prefix, not by splitting
// on the first underscore: a tool name may contain underscores of its own, and
// splitting would invent a plugin nobody declared.
func TestAToolIsFoundByItsPluginsNameNotByASplit(t *testing.T) {
	pluginsMu.Lock()
	saved := running
	running = []*plugin{{
		entry: PluginEntry{Name: "browser"},
		tools: []mcp.Tool{{Name: "browser_open_tab"}, {Name: "browser_close"}},
	}}
	pluginsMu.Unlock()
	defer func() {
		pluginsMu.Lock()
		running = saved
		pluginsMu.Unlock()
	}()

	p, tool, ok := findPluginTool("browser_open_tab")
	if !ok {
		t.Fatal("a tool with an underscore in its own name was not found")
	}
	if p.entry.Name != "browser" || tool != "open_tab" {
		t.Errorf("resolved to %s/%s, want browser/open_tab", p.entry.Name, tool)
	}

	// A name that looks like a prefix but is not one this plugin advertises.
	if _, _, ok := findPluginTool("browser_nothing"); ok {
		t.Error("a tool the plugin never advertised was resolved")
	}
	// And a built-in tool must never resolve to a plugin, which is what the
	// no-underscore rule on plugin names buys.
	if _, _, ok := findPluginTool("read_file"); ok {
		t.Error("a built-in tool resolved to a plugin")
	}
}

// The tools of a crashed plugin stay in the list. Removing them would leave an
// agent that had already read the list calling something that no longer exists
// and being told "unknown tool" — which is what a typo looks like, not what a
// crash looks like.
func TestACrashedPluginKeepsItsToolsListed(t *testing.T) {
	pluginsMu.Lock()
	saved := running
	running = []*plugin{{
		entry: PluginEntry{Name: "demo"},
		tools: []mcp.Tool{{Name: "demo_echo"}},
		dead:  "exit status 9",
	}}
	pluginsMu.Unlock()
	defer func() {
		pluginsMu.Lock()
		running = saved
		pluginsMu.Unlock()
	}()

	tools := pluginTools()
	if len(tools) != 1 || tools[0].Name != "demo_echo" {
		t.Fatalf("tools = %v, want the dead plugin's still listed", tools)
	}
	p, tool, ok := findPluginTool("demo_echo")
	if !ok {
		t.Fatal("the tool is listed and cannot be found")
	}
	res := callPluginTool(p, tool, nil, func(proto.GuestEvent) {})
	if !res.IsError {
		t.Fatal("a call to a dead plugin succeeded")
	}
	for _, want := range []string{"no longer running", "exit status 9", "unaffected"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the error does not say %q: %s", want, res.Content[0].Text)
		}
	}
}

// The other half of the collision the separator rule closes. A plugin named
// `read` exporting `file` would put a second `read_file` in tools/list that
// dispatch could never reach, because the built-in switch runs first — two
// entries with one name, one of them dead (F-D49).
func TestAPluginCannotShadowABuiltIn(t *testing.T) {
	for _, name := range []string{"exec", "read_file", "write_file", "list_dir",
		"upload", "download", "team_send", "team_peers", "team_spawn"} {
		if !builtinTool(name) {
			t.Errorf("%q is a built-in tool and is not recognised as one, so a plugin could "+
				"shadow it", name)
		}
	}
	// A namespaced name that is not a built-in must still be allowed, or the
	// check would cost every plugin its tools.
	for _, name := range []string{"demo_echo", "browser_navigate", "read_thing"} {
		if builtinTool(name) {
			t.Errorf("%q is not a built-in and was treated as one", name)
		}
	}
}

// The team tools count even in a sandbox that is not in a team: a name that
// would collide in a team must not be advertised out of one, or the same plugin
// would work in one sandbox and be silently short a tool in another.
func TestTheTeamToolsCountAsBuiltInEverywhere(t *testing.T) {
	saved := theTeam
	theTeam = nil
	defer func() { theTeam = saved }()
	if !builtinTool("team_send") {
		t.Error("team_send is not protected outside a team, so a plugin could take the name " +
			"in one sandbox and lose it in another")
	}
}

// The inward door records what the outward door records. A transcript that says
// which plugin was asked for which tool, and not with what, answers half the
// question a reader has (F-D49).
func TestPluginArgumentsAreRecordedAndRedacted(t *testing.T) {
	got := summarisePluginArgs([]byte(`{"url":"https://example.com","depth":2}`))
	if got != "depth=2 url=https://example.com" {
		t.Errorf("got %q, want the keys in order", got)
	}

	// Content never enters the record, on any tool, including one nobody here
	// has seen.
	body := strings.Repeat("secret", 100)
	got = summarisePluginArgs([]byte(`{"path":"/x","content":"` + body + `"}`))
	if strings.Contains(got, "secret") {
		t.Errorf("the record holds a plugin call's content:\n%s", got)
	}
	if !strings.Contains(got, "content=<600 bytes>") {
		t.Errorf("the summary does not size what it withheld:\n%s", got)
	}

	// And nothing at all is not an error.
	if summarisePluginArgs(nil) != "" {
		t.Error("a call with no arguments produced a summary")
	}
	if !strings.Contains(summarisePluginArgs([]byte(`{"broken":`)), "unparseable") {
		t.Error("malformed arguments were not reported as such")
	}
}
