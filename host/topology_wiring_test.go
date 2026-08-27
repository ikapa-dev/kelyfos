package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// team.topology has to be written exactly once per team, by the one
// function that raises one — raiseTeam — and every caller of raiseTeam has
// to reach it (docs/policy-record.md §3, §6).
//
// The gap this closes: nothing asserted team.topology gets written at all.
// There is exactly one recorder.NewTeamTopology call in the whole tree
// (host/team.go's raiseTeam) and, before this file, zero tests referenced
// it — the review that reopened P7-3 (F2) proved it by deleting that one
// line and watching the rest of the suite stay green.
// TestEverySessionStartSiteHasAMatchingSessionPolicy
// (policy_wiring_test.go) was built for exactly this reason on the
// session.policy side; the two tests below are its team.topology
// counterpart, reusing the same transitive-reachability machinery
// (reachesFunction, calleeName) generalised for a second target rather than
// duplicated — the identical hand-maintained-list lesson F1 and F3 already
// taught this phase, applied here before a third instance of it could be
// written by hand.
//
// Two separate properties, because a single-choke-point design like
// raiseTeam's is easy to break in either direction and neither failure
// looks like the other in a diff:
//
//   - TestEveryRaiseTeamCallerReachesTeamTopology catches a caller that
//     skips the choke point — a new door that boots a team some other way,
//     or a refactor that stops calling raiseTeam at all.
//   - TestRaiseTeamWritesTeamTopologyExactlyOnce catches the choke point
//     itself growing a duplicate — team.topology written once per agent
//     inside the existing per-agent loop, say, would still be reachable
//     (the first test would pass) and only a direct count catches it.

// funcsByNameAndFiles parses every non-test file in the host package once
// and returns every top-level function by name (for reachesFunction to
// recurse into) alongside the parsed files themselves, so callers do not
// each re-parse the package.
func funcsByNameAndFiles(t *testing.T) (map[string]*ast.FuncDecl, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the host package: %v", err)
	}

	funcsByName := map[string]*ast.FuncDecl{}
	var files []*ast.File
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, file)
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
					funcsByName[fn.Name.Name] = fn
				}
			}
		}
	}
	return funcsByName, files
}

func TestEveryRaiseTeamCallerReachesTeamTopology(t *testing.T) {
	funcsByName, files := funcsByNameAndFiles(t)
	if _, ok := funcsByName["raiseTeam"]; !ok {
		t.Fatal("no raiseTeam function found in the host package — this test is looking in the wrong place")
	}

	callers := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "raiseTeam" {
				continue
			}
			callsRaiseTeam := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && calleeName(call) == "raiseTeam" {
					callsRaiseTeam = true
				}
				return true
			})
			if !callsRaiseTeam {
				continue
			}
			callers++
			if !reachesFunction(fn, "NewTeamTopology", funcsByName, map[string]bool{}) {
				t.Errorf("func %s calls raiseTeam but never reaches recorder.NewTeamTopology — "+
					"directly, or through any function it calls — every caller of the one function "+
					"that raises a team has to reach the one function that records its topology "+
					"(docs/policy-record.md §3, §6)", fn.Name.Name)
			}
		}
	}
	if callers == 0 {
		t.Fatal("no caller of raiseTeam found in the host package — this test is looking in the wrong place")
	}
}

func TestRaiseTeamWritesTeamTopologyExactlyOnce(t *testing.T) {
	funcsByName, _ := funcsByNameAndFiles(t)
	raiseTeam, ok := funcsByName["raiseTeam"]
	if !ok {
		t.Fatal("no raiseTeam function found in the host package — this test is looking in the wrong place")
	}

	// A full ast.Inspect over the whole FuncDecl, including every nested
	// closure (broker.OnSpawn among them) — the same reach a duplicate call
	// hidden inside one of those closures would need to be caught, the
	// exact shape P7-2's own per-agent session.policy loop already showed
	// this codebase can produce by accident.
	n := 0
	ast.Inspect(raiseTeam, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && calleeName(call) == "NewTeamTopology" {
			n++
		}
		return true
	})
	if n != 1 {
		t.Fatalf("raiseTeam calls recorder.NewTeamTopology %d times, want exactly 1 — team.topology "+
			"describes the whole team and is written once at boot, not per agent and not on a "+
			"runtime spawn (docs/policy-record.md §3)", n)
	}
}
