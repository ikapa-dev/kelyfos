package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P7-17/F13(b): every loop that keeps a machine alive watches the recorder.
//
// This is an AST property rather than a grep. Deleting a `case <-rec.Broken():`
// from any of the loops below turns it red, which is what it is for.
//
// WHAT IT DOES NOT DO, stated because the first version of this comment claimed
// it did: it is a REGRESSION guard over an enumerated surface, not a discovery
// tool. It walks every non-test file in this package and recognises a
// machine-lifetime select two ways — by the channel names the existing loops
// use, and by being inside one of the functions named in lifetimeFuncs, where
// EVERY multi-way select must watch the recorder whatever its channels are
// called. A brand-new waiting loop, in a new function, on channels named
// something else, is invisible to both and always will be: no syntactic rule
// can tell "waits for a machine to end" from "waits for anything else". The
// review found exactly that gap by adding one, and the honest fix is to say so
// here rather than to keep widening a heuristic until it looks total.
//
// Named exemption, one, with its reason: stopChild is reached only AFTER that
// decision has been made, so it waits on childDone to end a command that is
// already being stopped.
var wiringExempt = map[string]string{
	"stopChild": "reached after the decision; it is ending a command that is already stopping",
}

// waitChannels are the receives that make a select a machine-lifetime loop.
var waitChannels = []string{"budgetFired", "vmExited", "childDone"}

// lifetimeFuncs are the functions that hold a machine open. Inside these, every
// select with more than one communication clause has to watch the recorder,
// whatever its channels are named — which is the half that catches a rename.
// Their existence is asserted, so a function renamed out from under this list
// fails rather than silently emptying it.
var lifetimeFuncs = []string{"runWithSandbox", "teamUp"}

func TestF13b_EveryMachineLifetimeLoopWatchesTheRecorder(t *testing.T) {
	checked := 0
	seenFunc := map[string]bool{}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if why, skip := wiringExempt[fn.Name.Name]; skip {
				t.Logf("exempt: %s — %s", fn.Name.Name, why)
				return false
			}
			inLifetimeFunc := false
			for _, name := range lifetimeFuncs {
				if fn.Name.Name == name {
					inLifetimeFunc = true
					seenFunc[name] = true
				}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectStmt)
				if !ok {
					return true
				}
				// Two ways in: the channel names the existing loops use, or
				// being a multi-way select inside a function that holds a
				// machine open — the second is what survives a rename.
				byName := isLifetimeSelect(fset, sel)
				byFunc := inLifetimeFunc && len(sel.Body.List) > 1
				if !byName && !byFunc {
					return true
				}
				checked++
				if !watchesBroken(fset, sel) {
					t.Errorf("%s:%d in %s waits for a machine to end and does not watch the "+
						"flight recorder.\n  Add `case <-rec.Broken():` — a sandbox nobody is "+
						"recording is one this CLI stops (P7-17/F13(b)).",
						file, fset.Position(sel.Pos()).Line, fn.Name.Name)
				}
				return true
			})
			return false
		})
	}
	// The three the coordinator located, and no fewer: a rule that stopped
	// finding any loop at all would pass silently.
	// run.go's two: the trailing-command form and the interactive form. The
	// team's own wait is on ctx.Done() alone and is checked by name below. A
	// rule that stopped finding any loop would otherwise pass silently.
	if checked < 2 {
		t.Errorf("only %d machine-lifetime loops were found; run.go has two. "+
			"The AST walk is looking in the wrong place.", checked)
	}
	// And the by-function half is only worth anything while the functions it
	// names exist. A rename empties it silently otherwise.
	for _, name := range lifetimeFuncs {
		if !seenFunc[name] {
			t.Errorf("lifetimeFuncs names %s and no such function is declared in this package; "+
				"the rename that moved it also emptied half of this guard", name)
		}
	}
}

// teamUp's wait is on ctx.Done() alone, so it does not match waitChannels. It
// is checked by name, because it is the team's whole run loop.
func TestF13b_TheTeamWaitWatchesTheRecorder(t *testing.T) {
	src, err := os.ReadFile("team.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "team.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	found, watched := false, false
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "teamUp" {
			return true
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectStmt); ok && watchesBroken(fset, sel) {
				watched = true
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatal("teamUp not found in team.go; this test is checking nothing")
	}
	if !watched {
		t.Error("teamUp waits for the team to end and does not watch the flight recorder. " +
			"A team has one recorder for the whole rig, so a failure there means every machine " +
			"in it is running unrecorded (P7-17/F13(b)).")
	}
}

func isLifetimeSelect(fset *token.FileSet, sel *ast.SelectStmt) bool {
	for _, c := range sel.Body.List {
		for _, name := range waitChannels {
			if strings.Contains(nodeText(fset, c.(*ast.CommClause).Comm), name) {
				return true
			}
		}
	}
	return false
}

func watchesBroken(fset *token.FileSet, sel *ast.SelectStmt) bool {
	for _, c := range sel.Body.List {
		if strings.Contains(nodeText(fset, c.(*ast.CommClause).Comm), ".Broken()") {
			return true
		}
	}
	return false
}

func nodeText(fset *token.FileSet, n ast.Node) string {
	if n == nil {
		return ""
	}
	start, end := fset.Position(n.Pos()), fset.Position(n.End())
	src, err := os.ReadFile(start.Filename)
	if err != nil || end.Offset > len(src) {
		return ""
	}
	return string(src[start.Offset:end.Offset])
}
