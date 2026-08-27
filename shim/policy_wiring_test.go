package shim

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The shim's own door (host/policy_wiring_test.go's docstring names all
// eight and explains why the criterion is WithPosture rather than
// session.start): (*Server).boot must call NewSessionPolicy in the same
// scope it calls WithPosture, or a shim-created machine's session.ready
// would carry its posture with nothing beside it saying what it was
// permitted (P7-2, docs/policy-record.md §4, §9.3).
//
// One package, one door, so this does not need host's per-function
// granularity — a per-file check is enough here, in the shape
// TestEveryFileThatBuildsAProxyWiresItsAudit already uses in host — but it
// is still a source scan rather than a fixed assertion about (*Server).boot
// by name, so a second door added to this package later is caught the same
// way rather than needing this test remembered and extended by hand.
func TestEveryWithPostureCallHasAMatchingSessionPolicy(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the shim package: %v", err)
	}

	withPosture := map[string]bool{}
	sessionPolicy := map[string]bool{}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "WithPosture":
					withPosture[name] = true
				case "NewSessionPolicy":
					sessionPolicy[name] = true
				}
				return true
			})
		}
	}

	if len(withPosture) == 0 {
		t.Fatal("no WithPosture call found in the shim package — this test is looking in the wrong place")
	}
	for file := range withPosture {
		if !sessionPolicy[file] {
			t.Errorf("%s calls WithPosture and never NewSessionPolicy, so a machine it creates would "+
				"have its posture recorded with nothing beside it saying what it was permitted — "+
				"docs/policy-record.md §4, §9.3.", file)
		}
	}
}
