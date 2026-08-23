package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The team tools make one promise beyond wrapping E2: capacity is grantable,
// topology is not. Most of what is worth testing without machines is that the
// promise is kept in the shape of the surface, and that each refusal says which
// case it is.

// The absence of parameters on team_up is the feature, so it is pinned.
func TestTeamToolsTakeNoTopology(t *testing.T) {
	want := map[string]bool{"team_up": true, "team_ps": true, "team_down": true}
	for _, tool := range hostToolDefinitions() {
		if !want[tool.Name] {
			continue
		}
		delete(want, tool.Name)
		if len(tool.InputSchema.Properties) != 0 {
			t.Errorf("%s takes %v, and the topology is the file's", tool.Name, tool.InputSchema.Properties)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing team tools: %v", want)
	}
	for _, tool := range hostToolDefinitions() {
		switch tool.Name {
		case "team_add_agent", "team_edge", "team_spawn", "team_set_budget":
			t.Errorf("%q exists, and no tool here may change a team's shape (F-D5)", tool.Name)
		}
	}
}

// A project with no [team] section gets an answer that says what a team is and
// where it would be written, rather than "not found".
func TestTeamUpWithoutADeclaredTeam(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	res := s.toolTeamUp()
	if !res.IsError {
		t.Fatal("a team was raised from a policy that declares none")
	}
	for _, want := range []string{"[team]", "kelyfos.toml", "docs/teams.md"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.Content[0].Text)
		}
	}
}

func TestTeamPSAndDownWithNoTeam(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	s := serverWith(t, policy)
	if res := s.toolTeamPS(); !res.IsError || !strings.Contains(res.Content[0].Text, "team_up") {
		t.Errorf("team_ps with no team does not point at team_up:\n%s", res.Content[0].Text)
	}
	if res := s.toolTeamDown(); !res.IsError || !strings.Contains(res.Content[0].Text, "no team") {
		t.Errorf("team_down with no team does not say so:\n%s", res.Content[0].Text)
	}
}

// A team somebody else raised is theirs to stop, exactly as a sandbox somebody
// else started is.
func TestTeamDownRefusesAnotherOwnersTeam(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "someone-elses", PID: 424242, Owner: ownerCLI})
	s := serverWith(t, policy)
	res := s.toolTeamDown()
	if !res.IsError {
		t.Fatal("a team this server did not raise was retired through it")
	}
	for _, want := range []string{"someone-elses", "424242", "kelyfos team down"} {
		if !strings.Contains(res.Content[0].Text, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, res.Content[0].Text)
		}
	}
}

// And the reverse: `kelyfos team down` must not signal a serve-mcp server,
// because that process is holding sandboxes the person did not ask to stop.
func TestCLITeamDownRefusesAServerOwnedTeam(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeTeamState(t, teamState{Name: "served", PID: os.Getpid(), Owner: ownerServeMCP})
	err := teamDown(nil)
	if err == nil {
		t.Fatal("the CLI signalled a team held by a serve-mcp server")
	}
	for _, want := range []string{"serve-mcp", "team_down"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// teamMembers is what both doors render from, so its handling of a machine that
// is gone has to be a fact rather than a hole.
func TestTeamMembersMarkAMissingSandbox(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	st := teamState{Name: "t", Edges: []string{"master -> worker-1"}}
	st.Agents = append(st.Agents, struct {
		Name    string `json:"name"`
		Sandbox string `json:"sandbox"`
		Via     string `json:"via,omitempty"`
	}{"master", "deadbeef", "cold"})
	rows := teamMembers(&st)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].Alive || rows[0].Sampled {
		t.Error("a sandbox that does not exist was reported as alive")
	}
	if len(rows[0].Reaches) != 1 || rows[0].Reaches[0] != "worker-1" {
		t.Errorf("reaches = %v, want the declared edge", rows[0].Reaches)
	}
}

func writeTeamState(t *testing.T, st teamState) {
	t.Helper()
	st.StartedAt = time.Now()
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	path := teamStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Nothing on the team path may write to this process's standard output.
//
// serve-mcp's stdout is the protocol, and one line of prose in the middle of it
// is a stream the client can no longer parse. The first live run of team_down
// did exactly that: a workspace write-back printed into the JSON. Reading the
// source is the only way to check it, because the failure needs five real
// machines to reproduce and none to introduce.
func TestTheTeamPathNeverWritesToStdout(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "team.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Everything raiseTeam calls, directly or through a goroutine it starts.
	// The three command-line entry points are deliberately absent: printing is
	// what they are for.
	quiet := map[string]bool{
		"raiseTeam": true, "stop": true, "bootAgent": true, "forkAgent": true,
		"bootTemplate": true, "storeTemplate": true, "describeAgent": true,
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || !quiet[fn.Name.Name] {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "fmt" {
				return true
			}
			switch sel.Sel.Name {
			case "Print", "Printf", "Println":
				found = append(found, fmt.Sprintf("%s writes to stdout at %s",
					fn.Name.Name, fset.Position(call.Pos())))
			}
			return true
		})
		return true
	})
	if len(found) > 0 {
		t.Errorf("serve-mcp's stdout is the protocol, so these must take a writer:\n  %s",
			strings.Join(found, "\n  "))
	}
}
