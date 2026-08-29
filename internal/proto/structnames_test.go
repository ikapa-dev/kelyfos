package proto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// protoStructNames is every struct type declared in this package's own
// non-test source. Read from the source rather than restated, so the
// completeness check in guestframes_test.go cannot go stale by omission —
// which is how the interface it checks came to be missing in the first place.
func protoStructNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				ts, ok := n.(*ast.TypeSpec)
				if !ok {
					return true
				}
				if _, ok := ts.Type.(*ast.StructType); ok {
					out = append(out, ts.Name.Name)
				}
				return true
			})
		}
	}
	if len(out) == 0 {
		t.Fatal("no struct types found; the parser is looking in the wrong place")
	}
	return out
}
