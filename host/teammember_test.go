package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
	"github.com/ikapa-dev/kelyfos/internal/team"
)

// Being wired to the broker is what makes a machine a member of a team, and
// every member's guest events belong in the team's record. So a sandbox built
// with an OnTeamRequest and no OnGuestEvent is a member whose OOM kills and
// plugin calls reach nobody.
//
// This is the guard for a bug that had already shipped. bootAgent installed the
// handler and forkAgent, which builds the same kind of machine from a snapshot
// instead of from cold, did not — and internal/sandbox drops the frame when the
// handler is nil, silently, because a guest that reports nothing and a host that
// listens to nothing look identical from the host's side. Forking is reserved
// for agents with no egress, so the members that lost their records were exactly
// the replica workers a `count` group creates.
//
// Nothing caught it because the two option sets were two literals that happened
// to agree, and one of them stopped agreeing. They are one function now
// (memberOptions); this test says a second one may not quietly appear.
//
// Per function rather than per file, because team.go held both the site that
// wired the handler and the site that did not — a file-wide rule would have
// looked at team.go, found an OnGuestEvent in it, and passed. Same shape as
// TestEveryFileThatBuildsAProxyWiresItsAudit: read the source, do not trust a
// list.
func TestEveryMachineWiredToATeamAlsoReportsWhatItsGuestSees(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the host package: %v", err)
	}

	checked := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				var teamWired, eventsWired bool
				ast.Inspect(fn, func(n ast.Node) bool {
					// Either spelling counts: a key in a sandbox.Options
					// literal, or a field assigned on one afterwards, which is
					// how serve-mcp wires its own handler.
					var field string
					switch v := n.(type) {
					case *ast.KeyValueExpr:
						if id, ok := v.Key.(*ast.Ident); ok {
							field = id.Name
						}
					case *ast.SelectorExpr:
						field = v.Sel.Name
					}
					switch field {
					case "OnTeamRequest":
						teamWired = true
					case "OnGuestEvent":
						eventsWired = true
					}
					return true
				})
				if !teamWired {
					continue
				}
				checked++
				if !eventsWired {
					t.Errorf("%s builds a machine with a team channel and no guest-event "+
						"handler (%s): its OOM kills and plugin calls are in no lane and in no chain",
						fn.Name.Name, fset.Position(fn.Pos()))
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no machine with a team channel found in the host package — " +
			"this test is looking in the wrong place")
	}
}

// And the same thing said once at run time, because the source test above can
// only see the shape: what memberOptions actually returns is what every member
// of a team is built from, forked or not.
func TestAMemberIsGivenBothItsChannelsHoweverItsMachineStarted(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	rec, err := recorder.Open(sandbox.Root(), "session-under-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()

	topo, err := team.NewTopology([]string{"worker-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := plannedAgent{name: "worker-1", image: "dev",
		res: config.AgentResources{CPUs: 2, MemMiB: 512}}
	opts := memberOptions(a, "id-under-test", "x86_64", team.New(topo, false, nil), rec)

	if opts.OnGuestEvent == nil {
		t.Error("a team member is built with no guest-event handler, so the sandbox " +
			"will drop everything its guest reports")
	}
	if opts.OnTeamRequest == nil {
		t.Error("a team member is built with no team channel")
	}
	if opts.Agent != "worker-1" || opts.Session != rec.Session() {
		t.Errorf("member = %q in session %q, want worker-1 in the team's session %q",
			opts.Agent, opts.Session, rec.Session())
	}
}
