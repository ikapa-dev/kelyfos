package shim

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"strings"
	"testing"
)

// P7-17/A2 — the half of this item that COMPILES on the parent commit.
//
// It reads source rather than running a sandbox, so it builds against fb62db8
// and fails there on the finding itself: nothing in that tree watched a shim
// recorder at all. The behavioural tests in a2_test.go need the watcher and the
// stop channel, neither of which exists on the parent, so their result there is
// a build failure — stated rather than dressed up as a behavioural one.

// The unit tests above drive watchRecorder directly, which proves what it does
// and not that anything calls it. This is the other half: the function that
// opens a recorder in this package must also start a watcher for it.
//
// A source property rather than a run, because starting a real shim sandbox
// needs KVM and a built image. It is a regression guard over an enumerated
// surface and not a discovery tool — the same honest limit host's own F13(b)
// wiring guard states about itself: a recorder opened by some new function this
// walk does not reach is invisible to it. What it does catch is the two ways
// this wiring dies — the `go s.watchRecorder(...)` line deleted, and the
// recorder opened somewhere else in this package with nothing watching it.
func TestA2_EveryRecorderThisPackageOpensIsWatched(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "shim.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	opens := 0
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		src := &strings.Builder{}
		if err := printer.Fprint(src, fset, fn.Body); err != nil {
			t.Fatal(err)
		}
		body := src.String()
		if !strings.Contains(body, "recorder.Open(") {
			return false
		}
		opens++
		if !strings.Contains(body, "go s.watchRecorder(") {
			t.Errorf("shim.go:%d: %s opens a flight recorder and starts no watcher for it.\n"+
				"  A shim sandbox whose recorder fails otherwise keeps running: commands\n"+
				"  executed, egress made, nothing recorded, nobody told (P7-17/A2, F13).",
				fset.Position(fn.Pos()).Line, fn.Name.Name)
		}
		return false
	})
	if opens != 1 {
		t.Errorf("%d functions in shim.go open a recorder; boot is the one that should. "+
			"The walk is looking in the wrong place, or a second one appeared.", opens)
	}
}
