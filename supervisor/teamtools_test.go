package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The tools E2-2 and E2-5 name, with the shapes a model is handed. Checked by
// name because a renamed tool is a silently broken agent: the model calls what
// the list said and gets "unknown tool".
func TestTeamToolsAreTheOnesTheSpecNames(t *testing.T) {
	want := map[string]bool{
		"team_send": true, "team_recv": true, "team_ask": true,
		"team_reply": true, "team_peers": true,
		"team_store_get": true, "team_store_put": true,
		"team_spawn": true, // E2-5, and only usable with a granted budget
	}
	got := map[string]bool{}
	for _, tool := range teamToolDefinitions(true) {
		got[tool.Name] = true
		if tool.Description == "" || tool.Title == "" {
			t.Errorf("%s has no description a model could act on", tool.Name)
		}
		if !isTeamTool(tool.Name) {
			t.Errorf("%s is in the team list but isTeamTool says otherwise", tool.Name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing tool %s", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("unexpected tool %s", name)
		}
	}
}

// A question has to arrive as something a model can answer without being taught
// a protocol: the tag comes back in the result, with a note saying what to do
// with it.
func TestRequiredArgumentsAreDeclared(t *testing.T) {
	required := map[string][]string{
		"team_send":      {"to", "body"},
		"team_ask":       {"to", "body"},
		"team_reply":     {"correlate", "body"},
		"team_store_get": {"key"},
		"team_store_put": {"key", "value"},
	}
	for _, tool := range teamToolDefinitions(true) {
		want, ok := required[tool.Name]
		if !ok {
			continue
		}
		have := map[string]bool{}
		for _, r := range tool.InputSchema.Required {
			have[r] = true
		}
		for _, r := range want {
			if !have[r] {
				t.Errorf("%s does not require %q", tool.Name, r)
			}
			if _, ok := tool.InputSchema.Properties[r]; !ok {
				t.Errorf("%s requires %q but does not describe it", tool.Name, r)
			}
		}
	}
}

// Nothing in the guest decides anything about a team, so a sandbox that is not
// in one must fail every team tool with a sentence rather than a nil panic.
func TestTeamToolsOnANonTeamSandboxRefusePolitely(t *testing.T) {
	for _, name := range []string{"team_send", "team_recv", "team_peers", "team_store_get"} {
		res := callTeamTool(nil, name, json.RawMessage(`{}`))
		if res == nil || !res.IsError {
			t.Fatalf("%s did not report an error off a team", name)
		}
		if !strings.Contains(res.Content[0].Text, "not part of a team") {
			t.Errorf("%s said %q", name, res.Content[0].Text)
		}
	}
}

func TestUnknownTeamToolIsNamed(t *testing.T) {
	c := &teamClient{agent: "master"}
	res := callTeamTool(c, "team_teleport", json.RawMessage(`{}`))
	if res == nil || !res.IsError || !strings.Contains(res.Content[0].Text, "team_teleport") {
		t.Errorf("result = %+v", res)
	}
}

// isTeamTool is what keeps the dispatch one switch instead of two lists that
// can disagree, so it must not claim tools that are not team tools.
func TestIsTeamToolDoesNotOverreach(t *testing.T) {
	for _, name := range []string{"exec", "read_file", "write_file", "list_dir", "upload", "download"} {
		if isTeamTool(name) {
			t.Errorf("isTeamTool claimed %q", name)
		}
	}
	if isTeamTool("team_") {
		t.Error("isTeamTool claimed the bare prefix")
	}
}

// An agent with no spawn budget is not shown a tool that could only refuse it.
func TestSpawnToolIsListedOnlyWithABudget(t *testing.T) {
	for _, tool := range teamToolDefinitions(false) {
		if tool.Name == "team_spawn" {
			t.Fatal("team_spawn is listed for an agent that has no budget for it")
		}
	}
	found := false
	for _, tool := range teamToolDefinitions(true) {
		found = found || tool.Name == "team_spawn"
	}
	if !found {
		t.Error("team_spawn is missing for an agent that was granted a budget")
	}
}
