package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// Everything bootAgent builds for a member has to come back off it when the
// boot fails, and the machine is part of "everything".
//
// This is the guard for a bug that had already shipped. bootAgent's failure
// defer released the proxy, the TAP, the cgroup child and the workspace image,
// and said nothing about rig.sb — so a `Start` that failed returned with a
// jailed Firecracker still up, its run directory on disk and its unix listeners
// and accept goroutines running for as long as the host did. The two failures
// after it compensated by hand, which is what made the gap look deliberate.
//
// It matters here more than at any other boot site because bootAgent is the one
// caller of sandbox.New whose process survives its own failure: a spawn request
// arrives from a guest through the broker, the error goes back to the agent
// that asked, and the team runs on. One leak per refused spawn, up to the
// budget, in a process that is not going to exit and reclaim them (finding
// L-7).
//
// The rule is written as "what the boot fills, the failure empties" rather than
// as "the defer mentions sb", because the way this was reached is the way it
// will be reached again: agentRig grows a field, one boot site learns to fill
// it, and the unwind twenty lines above is not where anyone looks.
func TestEverythingBootAgentBuildsIsReleasedWhenTheBootFails(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "team.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing team.go: %v", err)
	}

	var boot *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "bootAgent" {
			boot = fn
		}
	}
	if boot == nil {
		t.Fatal("bootAgent is not in team.go — this test is looking in the wrong place")
	}

	// What the boot fills: every `rig.x = …` in the function.
	filled := map[string]bool{}
	ast.Inspect(boot, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if f := rigField(lhs); f != "" {
				filled[f] = true
			}
		}
		return true
	})
	if len(filled) == 0 {
		t.Fatal("bootAgent fills no field of its rig — this test is looking in the wrong place")
	}

	// What the failure empties: every `rig.x` named anywhere inside the defer
	// that runs when ok is false.
	var unwind *ast.DeferStmt
	ast.Inspect(boot, func(n ast.Node) bool {
		if d, ok := n.(*ast.DeferStmt); ok && unwind == nil {
			unwind = d
		}
		return true
	})
	if unwind == nil {
		t.Fatal("bootAgent has no failure defer at all")
	}
	released := map[string]bool{}
	ast.Inspect(unwind, func(n ast.Node) bool {
		if f := rigField(n); f != "" {
			released[f] = true
		}
		return true
	})

	for field := range filled {
		if !released[field] {
			t.Errorf("bootAgent sets rig.%s and its failure defer never mentions it, so a boot that "+
				"fails after that line leaves it behind — and this is the one boot in the product "+
				"whose caller keeps running afterwards. Release it there, in the reverse of the order "+
				"it was built.", field)
		}
	}
}

// rigField names the field when this node is a selector on the boot's rig.
func rigField(n ast.Node) string {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == "rig" {
		return sel.Sel.Name
	}
	return ""
}

// A member is stopped once, however many callers decide it is time.
//
// Three of them can, and none is serialised against the others: teardown walks
// the roster, a max_runtime timer stops the member it was given, and a spawn
// lifetime stops the worker it was given. The timers run in goroutines nobody
// waits for, and one already past its select does not see the team's context
// close — so Ctrl-C at the instant a timer fires runs stop() twice on one rig.
//
// The cost is not the double shutdown. It is that stop() ends in a workspace
// sync-back, and a sync-back is not reentrant: two of them share one staging
// tree and one .kelyfos-previous, and the second's removal of that backup
// deletes the host directory the first has just renamed into it. That is the
// person's project, not a temporary (finding M-4).
//
// The receipt is the countable half. It is appended immediately before the
// shutdown, one per agent per teardown, into the team's chain — so a chain
// holding two receipts for one member is a member that was stopped twice, and
// this asserts it holds one.
func TestAMemberIsStoppedOnceHoweverManyCallersAskForIt(t *testing.T) {
	root := t.TempDir()
	rec, err := recorder.Open(root, "team-session")
	if err != nil {
		t.Fatal(err)
	}

	// A rig with no plumbing and a machine that was never started: Shutdown on
	// one of those signals nothing and cleans up nothing, which is what makes
	// the teardown path testable off a microVM at all. The PID is this test's
	// own, and it is there for one reason — the receipt is taken only when the
	// usage sample succeeds, and a sample needs a process to name.
	rig := &agentRig{
		name: "master",
		rec:  rec,
		sb:   &sandbox.Sandbox{State: sandbox.State{ID: "sb-1", PID: os.Getpid()}},
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = rig.stop(time.Second, &bytes.Buffer{})
		}()
	}
	wg.Wait()
	rec.Close()

	blob, err := os.ReadFile(recorder.Path(root, "team-session"))
	if err != nil {
		t.Fatal(err)
	}
	events, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("the team's chain did not survive four stops at once: %v", err)
	}
	receipts := 0
	for _, ev := range events {
		if ev.Type == recorder.TypeResourceSummary && ev.Agent == "master" {
			receipts++
		}
	}
	if receipts != 1 {
		t.Errorf("four callers stopped one member and the team's chain holds %d resource receipts for "+
			"it, not 1: stop() ran more than once, and its tail is a workspace sync-back that destroys "+
			"the host directory when two of them overlap", receipts)
	}
}
