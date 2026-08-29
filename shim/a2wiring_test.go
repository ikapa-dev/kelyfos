package shim

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
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

// shimFiles is every non-test Go file in this package.
//
// The whole package and not shim.go alone (P7-17/A2, review round). The first
// version parsed one file by name, and the review walked around it by putting a
// second recorder.Open in a new file — invisible, and so was the count that was
// supposed to notice.
func shimFiles(t *testing.T) []string {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, n := range names {
		if !strings.HasSuffix(n, "_test.go") {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		t.Fatal("no non-test Go files were found in this package; the walk is looking in the " +
			"wrong place and would pass on anything")
	}
	return out
}

func bodyOf(t *testing.T, fset *token.FileSet, fn *ast.FuncDecl) string {
	t.Helper()
	var b strings.Builder
	if err := printer.Fprint(&b, fset, fn.Body); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Every box this package registers is watched, and watched by NAME.
//
// The rule is about the identifier, not about the substring (P7-17/A2, review
// round). The first version grepped the enclosing function for
// `go s.watchRecorder(`, and the review defeated it by changing the argument to
// `&box{}` — the substring is still there, the watcher watches a box with no
// recorder and returns immediately, and no sandbox is watched at all. So the
// box put into s.boxes and the box handed to the watcher have to be the same
// identifier.
//
// WHAT IT CANNOT SEE, stated rather than implied away: a watcher started on the
// right box and then immediately stopped, a registration through a helper that
// takes the box as a parameter, or a map other than s.boxes. No syntactic rule
// reaches those. What it does catch is the two ways this wiring has actually
// died — the line deleted, and the line kept with the wrong argument.
func TestA2_EveryRegisteredBoxIsWatchedByName(t *testing.T) {
	registrations := 0
	for _, file := range shimFiles(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			body := bodyOf(t, fset, fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
					return true
				}
				idx, ok := as.Lhs[0].(*ast.IndexExpr)
				if !ok {
					return true
				}
				sel, ok := idx.X.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "boxes" {
					return true
				}
				box, ok := as.Rhs[0].(*ast.Ident)
				if !ok {
					t.Errorf("%s:%d: %s registers something that is not a named box, so the "+
						"watcher below cannot be checked against it",
						file, fset.Position(as.Pos()).Line, fn.Name.Name)
					return true
				}
				registrations++
				want := "go s.watchRecorder("
				if !strings.Contains(body, want) {
					t.Errorf("%s:%d: %s registers a sandbox in s.boxes and starts no watcher "+
						"for it.\n  A shim sandbox whose recorder fails otherwise keeps "+
						"running: commands executed,\n  egress made, nothing recorded, nobody "+
						"told (P7-17/A2, F13).",
						file, fset.Position(as.Pos()).Line, fn.Name.Name)
					return true
				}
				// And on THAT box. `go s.watchRecorder(id, &box{})` contains
				// the substring and watches nothing.
				if !strings.Contains(body, ", "+box.Name+")") {
					t.Errorf("%s:%d: %s registers %s and the watcher it starts is not passed "+
						"%s.\n  A watcher on a different box is a watcher on no box "+
						"(P7-17/A2, review round).",
						file, fset.Position(as.Pos()).Line, fn.Name.Name, box.Name, box.Name)
				}
				return true
			})
			return false
		})
	}
	if registrations != 1 {
		t.Errorf("%d places register a sandbox in s.boxes; createSandbox is the one that "+
			"should. The walk is looking in the wrong place, or a second one appeared.",
			registrations)
	}
}

// The window before registration is closed by a check rather than by a watcher,
// and this pins that it exists.
//
// boot's three appends discard their errors like every other Append in this
// product, and every wireEgressAudit callback the machine has already made can
// latch the recorder too. Without the check, a box whose recorder died during
// boot is handed back to createSandbox, answered 201, and registered — a corpse
// holding one of MaxSandboxes for the life of the process, listed by GET
// /sandboxes and handed out by only() to every envd file call (P7-17/A2,
// review round).
func TestA2_TheBootThatOpensARecorderChecksItBeforeReturning(t *testing.T) {
	opens := 0
	for _, file := range shimFiles(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			body := bodyOf(t, fset, fn)
			if !strings.Contains(body, "recorder.Open(") {
				return false
			}
			opens++
			if !strings.Contains(body, ".Failure()") {
				t.Errorf("%s:%d: %s opens a flight recorder and hands the box back without "+
					"asking whether it still works.\n  Every append between the Open and the "+
					"registration discards its error, so a box whose\n  recorder died while "+
					"booting is registered and never removed (P7-17/A2).",
					file, fset.Position(fn.Pos()).Line, fn.Name.Name)
			}
			return false
		})
	}
	if opens != 1 {
		t.Errorf("%d functions in this package open a recorder; boot is the one that should. "+
			"The walk is looking in the wrong place, or a second one appeared.", opens)
	}
}

// A shim built with no writer seam prints to the process's stderr, which is
// what a real run wants and what no assertion can reach.
func TestA2_TheDefaultWriterIsStderr(t *testing.T) {
	if got := New(Policy{}).stderr(); got != os.Stderr {
		t.Errorf("a Server with no errw writes to %v, want os.Stderr", got)
	}
}
