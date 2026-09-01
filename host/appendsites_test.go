package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// P7-17/F13(b): `_ = rec.Append(...)` cannot grow without somebody deciding to.
//
// The finding counted seventy-seven of these. They need no change to be
// CORRECT — since F13 the consequence of a failed Append lives inside the
// recorder (it latches and refuses everything after), and since F13(b) the run
// loops act on that latch. Each `_ =` is now a call whose error is genuinely
// handled elsewhere, which is a real answer rather than an excuse.
//
// The report offered two shapes and this is the one taken: a count that must
// not grow, rather than a rec.Must(e) at every site.
//
// Why not Must. It would have to DO something on failure at seventy-five call
// sites, and there are only two things it could do — panic, which a CLI must
// not, or return an error the caller has to handle, which is the seventy-five
// checks the recorder's latch exists to make unnecessary. Worse, naming the
// call Must would say at each site that the error is being acted on THERE. It
// is not: it is acted on in the select. This task has already been bitten twice
// by a comment that claimed more than its code did, and a function name is a
// comment that cannot be qualified.
//
// What this test buys instead is the property the owner asked for: a
// seventy-sixth site cannot appear without someone changing this number, in the
// same commit, having read why.
//
// It cannot pass silently. An equality on a count fails in both directions — a
// site removed and not accounted for fails too — which a "this pattern must not
// appear" assertion could not do.
//
// The walk counts both spellings — `_ = rec.Append(...)` and a bare
// `rec.Append(...)` whose error is dropped without even a blank. The first
// version counted only the former, which left a way past the number that
// changed no line of it.
//
// 75 → 78, audit of 2026-09-01 (A2/A3): the channel-credential refusals are
// recorded at three new sites — channelRefusedRecorder in host/plugins.go,
// servedBox.channelRefused in host/servemcp.go, and the late-wired closure in
// host/run.go — one per door shape. Each is a refusal the record is meant to
// hold, and each ignores the error for the reason every other site here does:
// a failed Append latches the recorder and the run loops act on that.
//
// 78 → 79, audit of 2026-09-01 (A4): wireProxyAudit records
// secret.unscrubbable — a compressed response from a credential-bound origin,
// where the echo suppression cannot read the body. The one event that says
// the value may have reached the guest.
const discardedAppendSites = 79

// discardedAppendPackages are the trees the finding counted.
var discardedAppendPackages = []string{"host", "internal", "shim"}

func TestTheDiscardedAppendCountDoesNotGrow(t *testing.T) {
	sites := findDiscardedAppends(t)
	if len(sites) == discardedAppendSites {
		return
	}
	sort.Strings(sites)
	t.Errorf("there are %d `_ = ....Append(...)` sites and discardedAppendSites says %d.\n\n"+
		"  MORE than the constant: a new one has been added. That is allowed — the recorder\n"+
		"  latches on first failure and the run loops stop the machine when it does, so the\n"+
		"  error is handled, elsewhere and once (P7-17/F13, F13(b)). But it is allowed on\n"+
		"  purpose rather than by habit: raise the number in the same commit.\n\n"+
		"  FEWER: one was removed or given a real check. Lower the number, in that commit.\n\n"+
		"  The sites:\n    %s",
		len(sites), discardedAppendSites, strings.Join(sites, "\n    "))
}

// findDiscardedAppends walks the trees by AST rather than by regular
// expression: `_ =` and `.Append(` on one line is a formatting accident away
// from being missed, and gofmt splits exactly these calls across lines.
func findDiscardedAppends(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pkg := range discardedAppendPackages {
		root := filepath.Join("..", pkg)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				var call *ast.CallExpr
				var pos token.Pos
				switch st := n.(type) {
				case *ast.AssignStmt:
					// `_ = rec.Append(...)`
					if len(st.Lhs) != 1 || len(st.Rhs) != 1 {
						return true
					}
					id, ok := st.Lhs[0].(*ast.Ident)
					if !ok || id.Name != "_" {
						return true
					}
					call, _ = st.Rhs[0].(*ast.CallExpr)
					pos = st.Pos()
				case *ast.ExprStmt:
					// `rec.Append(...)` with the error dropped entirely, which
					// the first version of this walk missed: it looked only for
					// the `_ =` spelling, so a bare call was a way past the
					// count without changing the number.
					call, _ = st.X.(*ast.CallExpr)
					pos = st.Pos()
				default:
					return true
				}
				if call == nil {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Append" {
					return true
				}
				rel, _ := filepath.Rel("..", path)
				out = append(out, rel+":"+itoa(fset.Position(pos).Line))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no discarded Append sites found at all; the walk is looking in the wrong place")
	}
	return out
}
