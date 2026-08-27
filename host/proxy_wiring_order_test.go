package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestProxyWiringPrecedesGuestStart is the ordering half of
// TestEveryFileThatBuildsAProxyWiresItsAudit, which that test cannot be: it
// only proves wireProxyAudit/wireAudit is called SOMEWHERE in a file that
// builds a proxy, which says nothing about whether that call happens before
// or after the guest it is meant to audit is already running — the exact
// shape of the original bug this whole file exists to guard against, just
// relocated to a different one of the five sites that build a proxy.
// host/snapshot.go's own version of this check
// (TestSnapshotRestoreWiresAuditBeforeResume) is hard-coded to that one
// function because it is the site the bug actually shipped in; an external
// review found the other four were already correct by hand, and this test is
// what turns that one-time finding into something a future edit cannot
// silently undo.
//
// Same technique as TestSnapshotRestoreWiresAuditBeforeResume and
// TestEveryFileThatBuildsAProxyWiresItsAudit: read the source, do not trust a
// list — table-driven here because the same check now applies to four
// functions across three files rather than one.
func TestProxyWiringPrecedesGuestStart(t *testing.T) {
	cases := []struct {
		file, funcName string
	}{
		{"run.go", "runWithSandbox"},
		{"team.go", "bootAgent"},
		{"servemcptools.go", "boot"},
		{"servemcpstate.go", "toolRestore"},
	}

	for _, c := range cases {
		t.Run(c.file+"/"+c.funcName, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, c.file, nil, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", c.file, err)
			}

			var fn *ast.FuncDecl
			ast.Inspect(file, func(n ast.Node) bool {
				if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == c.funcName {
					fn = f
					return false
				}
				return true
			})
			if fn == nil {
				t.Fatalf("%s not found in %s — this test is looking in the wrong place", c.funcName, c.file)
			}

			var wirePos, startPos token.Pos
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					if fun.Name == "wireProxyAudit" {
						wirePos = call.Pos()
					}
				case *ast.SelectorExpr:
					switch fun.Sel.Name {
					case "wireAudit":
						wirePos = call.Pos()
					case "Start", "Restore":
						if startPos == token.NoPos {
							startPos = call.Pos()
						}
					}
				}
				return true
			})

			if wirePos == token.NoPos {
				t.Fatalf("%s no longer calls wireProxyAudit or wireAudit — a sandbox it creates "+
					"would record nothing about egress: no attempt, allowed or blocked, and no "+
					"credential use", c.funcName)
			}
			if startPos == token.NoPos {
				t.Fatalf("%s no longer calls Start or Restore — this test is looking in the wrong place", c.funcName)
			}
			if wirePos > startPos {
				t.Errorf("in %s, the guest is started or restored BEFORE its audit hooks are wired — "+
					"a resumed or newly started guest can round-trip over the control port and attempt "+
					"egress while OnEvent/OnSecret/OnWithheld are still nil, the exact unaudited window "+
					"S2 closed for host/snapshot.go; wire before starting or restoring", c.funcName)
			}
		})
	}
}
