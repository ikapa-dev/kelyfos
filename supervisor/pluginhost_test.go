package main

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode/utf8"

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

// A content key is redacted for its name, not for the type the value arrived
// as. A plugin's arguments are whatever the agent typed, so the agent picks the
// shape as well as the bytes — and a guard that recognised only a string let the
// same content back in wrapped in an object, written into the record whole under
// the key this code promises to hold by size (F-D49).
func TestPluginContentIsSizedWhateverShapeItArrivesIn(t *testing.T) {
	body := strings.Repeat("secret", 100)
	got := summarisePluginArgs([]byte(`{"content":{"smuggled":"` + body + `"}}`))
	if strings.Contains(got, "secret") {
		t.Errorf("an object under content was written into the record verbatim:\n%s", got)
	}
	// 600 bytes of body inside {"smuggled":"…"}, which is 15 bytes of JSON.
	if got != "content=<615 bytes>" {
		t.Errorf("got %q, want the object recorded by its size", got)
	}

	got = summarisePluginArgs([]byte(`{"stdin":["one","two"]}`))
	if strings.Contains(got, "one") {
		t.Errorf("an array under stdin was written into the record verbatim:\n%s", got)
	}
	if got != "stdin=<13 bytes>" {
		t.Errorf("got %q, want the array recorded by its size", got)
	}

	// A number is not content in any useful sense, but the rule is about the
	// key: a reader who sees `data=` is told a size, always, rather than being
	// told one on the calls where the caller happened to send a string.
	if got := summarisePluginArgs([]byte(`{"data":12345}`)); got != "data=<5 bytes>" {
		t.Errorf("got %q, want the number recorded by its size", got)
	}
}

// A summary has to fit the channel it leaves on.
//
// The agent's arguments arrive on the MCP channel, whose frames run to
// proto.MaxMCPLine — 16 MiB — and this report leaves on the events channel,
// bounded at proto.MaxLine, 1 MiB. proto.Writer measures before it writes, so an
// oversized report is not truncated, it is refused; and pumpEvents keeps a
// refused event as `pending` and offers it first on the next connection, where
// it is refused again. One call would have cost the sandbox every later event —
// plugin crashes, OOM kills, every other call — for as long as the machine ran.
func TestAPluginCallSummaryAlwaysFitsTheEventsChannel(t *testing.T) {
	huge := strings.Repeat("A", 9<<20)
	// Sized so that each of these on its own renders past proto.MaxLine: the
	// point is that no one of the three bounds carries the other two.
	elems := make([]string, 700000)
	for i := range elems {
		elems[i] = `"a"`
	}
	keys := make([]string, 120000)
	for i := range keys {
		keys[i] = fmt.Sprintf(`"k%06d":"v"`, i)
	}
	for _, tc := range []struct{ where, raw string }{
		{"under an argument key no tool declares", `{"x":{"a":"` + huge + `"}}`},
		{"spread over an array", `{"argv":[` + strings.Join(elems, ",") + `]}`},
		{"spread over many arguments", "{" + strings.Join(keys, ",") + "}"},
	} {
		t.Run(tc.where, func(t *testing.T) {
			ev := proto.GuestEvent{
				V: proto.Version, Type: proto.GuestEventPluginCall,
				Name: "browser", Tool: "navigate", Outcome: "ok",
				Args: summarisePluginArgs([]byte(tc.raw)),
			}
			if err := proto.NewWriter(io.Discard).Write(ev); err != nil {
				t.Fatalf("the report of a call carrying megabytes %s cannot be sent: %v", tc.where, err)
			}
		})
	}
}

// Each bound is checked on its own, because the line bound hides the others: an
// argument cut only by the last resort is one nobody can read next to the rest
// of the call.
func TestNoOnePluginArgumentCanFillTheLine(t *testing.T) {
	// The default branch, which marshalled an object with no length to stop at.
	got := summarisePluginArgs([]byte(`{"x":{"a":"` + strings.Repeat("A", 300) + `"}}`))
	if strings.Count(got, "A") > maxArgBytes {
		t.Errorf("an object argument was written out whole:\n%s", got)
	}
	// 300 bytes of body inside {"a":"…"}, which is 8 bytes of JSON.
	if !strings.Contains(got, "(308 bytes)") {
		t.Errorf("the truncated object does not say what it was cut from:\n%s", got)
	}

	// The array branch, which grows without any one element being long. Bounded
	// by maxArrayBytes rather than maxArgBytes: an array here is usually the
	// egress allowlist, which is recorded nowhere else, so the budget is
	// deliberately generous and the joined line's own cap is what keeps the
	// record a record (P6-28).
	elems := make([]string, 2000)
	for i := range elems {
		elems[i] = `"a"`
	}
	got = summarisePluginArgs([]byte(`{"argv":[` + strings.Join(elems, ",") + `]}`))
	if len(got) > maxArrayBytes+64 {
		t.Errorf("a 2000-element array rendered %d characters, which is not a log line:\n%s", len(got), got)
	}
	if !strings.Contains(got, "more)") {
		t.Errorf("the array does not say how many elements it left out:\n%s", got)
	}

	// And the case the budget exists for: a real allowlist survives whole. This
	// is the one an earlier bound cut short, and losing its last entry means
	// losing the only record of what the agent asked to reach.
	allow := `{"allow":["registry.npmjs.org","github.com","objects.githubusercontent.com",` +
		`"proxy.golang.org","sum.golang.org","pypi.org","files.pythonhosted.org","deb.debian.org"]}`
	if got := summarisePluginArgs([]byte(allow)); strings.Contains(got, "more)") {
		t.Errorf("an eight-domain allowlist was cut short:\n%s", got)
	} else if !strings.Contains(got, "deb.debian.org") {
		t.Errorf("the allowlist lost its last entry:\n%s", got)
	}

	// And a plugin's declared arguments are its own business, so the shapes the
	// built-in tools never send are exactly the ones that must stay bounded.
	if got := summarisePluginArgs([]byte(`{"count":3,"allow":["a.example","b.example"],"deep":{"x":1}}`)); got != `allow=[a.example,b.example] count=3 deep={"x":1}` {
		t.Errorf("got %q, want a small call rendered whole", got)
	}
}

// The line itself, because nothing bounds how many arguments a call has or how
// long one of their names is.
func TestTheWholePluginSummaryStaysALine(t *testing.T) {
	parts := make([]string, 2000)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"k%04d":"v"`, i)
	}
	got := summarisePluginArgs([]byte("{" + strings.Join(parts, ",") + "}"))
	if len(got) > maxArgsBytes+64 {
		t.Errorf("2000 short arguments rendered %d characters:\n%.200s…", len(got), got)
	}
	if !strings.Contains(got, "bytes)") {
		t.Errorf("the clipped summary does not say how long the whole thing was:\n%.200s…", got)
	}

	// One long key is the same hole with one argument in it.
	if got := summarisePluginArgs([]byte(`{"` + strings.Repeat("k", 1<<20) + `":1}`)); len(got) > maxArgsBytes+64 {
		t.Errorf("a one-megabyte key rendered %d characters", len(got))
	}
}

// Clipping happens on a rune boundary. The summary is marshalled onto the
// events channel and printed to somebody's terminal, and half a character is
// neither.
func TestPluginSummaryClippingNeverLeavesHalfARune(t *testing.T) {
	s := strings.Repeat("€", 10) // three bytes each
	for n := 0; n <= len(s); n++ {
		got := clipUTF8(s, n)
		if !utf8.ValidString(got) {
			t.Fatalf("clipping %d bytes of a multi-byte string left %q, which is not valid UTF-8", n, got)
		}
		if len(got) > n {
			t.Fatalf("clipping to %d bytes returned %d", n, len(got))
		}
	}
	// A replacement character the JSON decoder already substituted is a
	// character, and survives the clip like any other.
	if got := clipUTF8("ab�cd", 5); got != "ab�" {
		t.Errorf("got %q, want the replacement character kept", got)
	}
}
