package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Every file that builds an egress proxy must also wire it to a recorder.
//
// This is the guard for a bug that had already shipped. There are five proxies
// in this product; four of them wired `OnEvent` and `OnSecret` by hand, and the
// fifth — the one `kelyfos snapshot restore` builds — did not. A restored
// machine therefore wrote a session chain containing a start, a ready and an
// end and nothing at all in between: a blocked egress attempt left no trace, and
// a credential spent left no trace. The chain did not look broken. It looked
// finished.
//
// Nothing caught it because there was nothing to catch it with: the wiring was
// four copies of the same twenty lines, and a fifth site simply never grew
// them. The copies are one function now (wireProxyAudit), and this test says
// the function must actually be called.
//
// The rule is per file rather than per function on purpose. `restoreNetwork`
// builds the proxy and its caller wires it, which is legitimate — the recorder
// is keyed on a sandbox id that does not exist until the restore returns — and
// both live in snapshot.go. A file is the smallest unit that holds the whole
// arrangement.
//
// Same shape as internal/config's TestEveryKeyFunctionIsScanned: read the
// source, do not trust a list.
func TestEveryFileThatBuildsAProxyWiresItsAudit(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the host package: %v", err)
	}

	builds := map[string]bool{}
	wires := map[string]bool{}

	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.CompositeLit:
					// &egress.Proxy{...} — a selector expression naming the
					// egress package's Proxy type.
					if sel, ok := v.Type.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "egress" && sel.Sel.Name == "Proxy" {
							builds[name] = true
						}
					}
				case *ast.CallExpr:
					if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "wireProxyAudit" {
						wires[name] = true
					}
				}
				return true
			})
		}
	}

	if len(builds) == 0 {
		t.Fatal("no egress.Proxy construction found in the host package — this test is looking in the wrong place")
	}

	for file := range builds {
		if !wires[file] {
			t.Errorf("%s builds an egress.Proxy and never calls wireProxyAudit, so a sandbox it "+
				"creates would record nothing about egress — no attempt, allowed or blocked, and no "+
				"credential use. Wire it, or move the construction to a file that does.", file)
		}
	}
}
