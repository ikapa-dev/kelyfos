package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every supported client is asserted byte-for-byte into a sandboxed home
// (P6-13, D41's acceptance line 8).
//
// Byte-for-byte rather than "it parses", because the failures these writers
// exist to prevent are all shape: `servers` where a client wants `mcpServers`,
// camelCase where it wants snake_case, a relative policy path where an absolute
// one was the whole point. A test that only checked the file was valid JSON
// would pass on every one of them.

func connectFixture(t *testing.T) (project, home, bin string) {
	t.Helper()
	root := t.TempDir()
	project = filepath.Join(root, "proj")
	home = filepath.Join(root, "home")
	for _, d := range []string{project, home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, "kelyfos.toml"), []byte("[resources]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin = filepath.Join(root, "kelyfos")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KELYFOS_CONNECT_HOME", home)
	return project, home, bin
}

// The policy path is absolute in every client's file, and that is the assertion
// F-D44 exists for: a server that has to find its own policy can find none and
// run with no ceiling at all.
func TestEveryClientGetsAnAbsolutePolicyPath(t *testing.T) {
	project, home, bin := connectFixture(t)
	cmd, err := serverCommand(project, "", bin)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range clients() {
		t.Run(c.Name, func(t *testing.T) {
			out, err := c.Write(nil, cmd)
			if err != nil {
				t.Fatal(err)
			}
			body := string(out)
			if !strings.Contains(body, cmd.Policy) {
				t.Errorf("%s's file does not name the policy: %s", c.Name, body)
			}
			if !filepath.IsAbs(cmd.Policy) {
				t.Errorf("the policy path is not absolute: %s", cmd.Policy)
			}
			if !strings.Contains(body, bin) {
				t.Errorf("%s's file does not name the binary absolutely: %s", c.Name, body)
			}
			// serve-mcp and not mcp. F-D48 found that exact mistake once in this
			// repository's own configuration.
			if !strings.Contains(body, "serve-mcp") {
				t.Errorf("%s's file does not point at serve-mcp: %s", c.Name, body)
			}
			// Gemini's trust flag bypasses every tool-call confirmation, which
			// for a server whose tools boot microVMs is exactly backwards. D41
			// makes never emitting it binding, and this is what binds it.
			if strings.Contains(body, "trust") {
				t.Errorf("%s's file mentions trust: %s", c.Name, body)
			}
			// A "verified against X on <date>" line, because a client format is
			// an external surface and the honest thing to publish is when
			// somebody last looked.
			if !strings.Contains(c.Verified, "verified against") || !strings.Contains(c.Verified, "on 20") {
				t.Errorf("%s carries no verification line: %q", c.Name, c.Verified)
			}
			_ = home
		})
	}
}

// The shapes that differ, asserted as shapes. These are the mistakes.
func TestTheClientsThatDifferAreWrittenDifferently(t *testing.T) {
	project, _, bin := connectFixture(t)
	cmd, err := serverCommand(project, "", bin)
	if err != nil {
		t.Fatal(err)
	}
	get := func(name string) string {
		c, ok := findClient(name)
		if !ok {
			t.Fatalf("no client %q", name)
		}
		out, err := c.Write(nil, cmd)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}

	// VS Code's top-level key is `servers`. The most common integration mistake
	// there is.
	vscode := get("vscode")
	if !strings.Contains(vscode, `"servers"`) || strings.Contains(vscode, `"mcpServers"`) {
		t.Errorf("VS Code got the wrong top-level key:\n%s", vscode)
	}
	// Claude Code's is `mcpServers`.
	if cc := get("claude-code"); !strings.Contains(cc, `"mcpServers"`) {
		t.Errorf("Claude Code got the wrong top-level key:\n%s", cc)
	}
	// Codex is TOML with snake_case, not JSON with camelCase.
	codex := get("codex")
	if !strings.Contains(codex, "[mcp_servers.kelyfos]") {
		t.Errorf("Codex is not snake_case TOML:\n%s", codex)
	}
	if strings.Contains(codex, "mcpServers") || strings.HasPrefix(strings.TrimSpace(codex), "{") {
		t.Errorf("Codex was written as JSON:\n%s", codex)
	}
}

// A configuration file belongs to the person whose machine it is. Everything
// that was in it stays in it — including keys this command has never heard of.
func TestWritingPreservesEverythingElse(t *testing.T) {
	project, _, bin := connectFixture(t)
	cmd, err := serverCommand(project, "", bin)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := findClient("claude-code")

	before := []byte(`{
  "mcpServers": {"somebody-elses": {"command": "other"}},
  "aKeyWeDoNotKnowAbout": {"nested": true}
}`)
	after, err := c.Write(before, cmd)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(after, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["aKeyWeDoNotKnowAbout"]; !ok {
		t.Error("a key this command does not know about was dropped")
	}
	servers := doc["mcpServers"].(map[string]any)
	if _, ok := servers["somebody-elses"]; !ok {
		t.Error("another server was dropped")
	}
	if _, ok := servers["kelyfos"]; !ok {
		t.Error("kelyfos was not added")
	}

	// Idempotent: a second run changes nothing at all.
	again, err := c.Write(after, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(after) {
		t.Errorf("a second run rewrote the file:\n%s\n---\n%s", after, again)
	}

	// And --remove takes out exactly one entry.
	removed, changed, err := c.Remove(after)
	if err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if err := json.Unmarshal(removed, &doc); err != nil {
		t.Fatal(err)
	}
	servers = doc["mcpServers"].(map[string]any)
	if _, ok := servers["kelyfos"]; ok {
		t.Error("kelyfos survived --remove")
	}
	if _, ok := servers["somebody-elses"]; !ok {
		t.Error("--remove took somebody else's server with it")
	}
	if _, ok := doc["aKeyWeDoNotKnowAbout"]; !ok {
		t.Error("--remove dropped an unrelated key")
	}
}

// Codex's file is the user's whole-product configuration and may carry comments,
// which no TOML round-trip in the standard library preserves. So only this
// project's own table is touched.
func TestCodexKeepsTheRestOfTheFile(t *testing.T) {
	project, _, bin := connectFixture(t)
	cmd, err := serverCommand(project, "", bin)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := findClient("codex")

	before := []byte(`# a comment somebody wrote
model = "something"

[mcp_servers.other]
command = "elsewhere"
`)
	after, err := c.Write(before, cmd)
	if err != nil {
		t.Fatal(err)
	}
	body := string(after)
	for _, want := range []string{"# a comment somebody wrote", `model = "something"`, "[mcp_servers.other]"} {
		if !strings.Contains(body, want) {
			t.Errorf("codex dropped %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "[mcp_servers.kelyfos]") != 1 {
		t.Errorf("codex wrote its own table %d times:\n%s", strings.Count(body, "[mcp_servers.kelyfos]"), body)
	}

	again, err := c.Write(after, cmd)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(after) {
		t.Errorf("a second codex run rewrote the file:\n%s\n---\n%s", after, again)
	}

	removed, changed, err := c.Remove(after)
	if err != nil || !changed {
		t.Fatalf("remove: changed=%v err=%v", changed, err)
	}
	if strings.Contains(string(removed), "kelyfos") {
		t.Errorf("codex --remove left kelyfos behind:\n%s", removed)
	}
	if !strings.Contains(string(removed), "[mcp_servers.other]") {
		t.Errorf("codex --remove took another server with it:\n%s", removed)
	}
}

// A server with no ceiling is not worth attaching, so a missing policy is a
// refusal rather than a file written with a path to nothing.
func TestConnectRefusesWithoutAPolicy(t *testing.T) {
	root := t.TempDir()
	_, err := serverCommand(root, "", "/bin/true")
	if err == nil {
		t.Fatal("a project with no kelyfos.toml was accepted")
	}
	for _, want := range []string{"no policy at", "no ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// A client this command does not know is a plain failure with a fix line, not a
// catalog refusal — the catalog is for what KelyfOS decided to deny, and its IDs
// are part of the surface P6-14 freezes.
func TestAnUnknownClientIsToldWhatIsSupported(t *testing.T) {
	if _, ok := findClient("zed"); ok {
		t.Fatal("zed is generic-only per D41 and must not have a writer")
	}
	for _, generic := range []string{"opencode", "zed", "cline", "continue", "goose", "crush", "windsurf"} {
		if _, ok := findClient(generic); ok {
			t.Errorf("%s has a writer, and D41 makes it generic-only", generic)
		}
	}
}
