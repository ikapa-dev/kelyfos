package recorder

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestSchemaDocumentsEveryFieldTheHostWrites is the reverse of
// TestSchemaFieldsExist: that one checks the schema names only real struct
// fields; this one checks the host does not WRITE a field the schema forgets to
// describe. A consumer builds on the generated reference, so a field the host
// sets and the reference omits is a fact about the session no reader is told to
// look for.
//
// It reads the host's own source — every recorder.Event{...} composite literal
// under ../../host — and, for each event type, requires the schema to document
// every payload field set on it. It fails on main-before-this-fix for two:
// channel.refused carries `agent` (host/plugins.go) and egress.attempt carries
// `error` (host/denials.go), neither of which the schema described. The general
// property is what keeps a third from slipping in: a field added at a door
// without a schema row fails here, in the commit that adds it.
//
// Only literals whose Type is a recorder.Type* constant are checked; a partial
// literal that fills Type in later (host/plugins.go's plugin-event base) is
// skipped rather than guessed at.
func TestSchemaDocumentsEveryFieldTheHostWrites(t *testing.T) {
	nameToType := map[string]string{}
	for v, name := range typeConstants(t) {
		nameToType[name] = v
	}

	// json tag for every Go field name on Event, so a literal key (Agent) maps
	// to what the schema names it (agent).
	fieldJSON := map[string]string{}
	rt := reflect.TypeOf(Event{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			fieldJSON[f.Name] = name
		}
	}

	// What the schema documents: the common fields, plus each type's own.
	documented := map[string]map[string]bool{}
	common := map[string]bool{}
	for _, f := range CommonFields() {
		common[f.Name] = true
	}
	for _, et := range Types() {
		set := map[string]bool{}
		for _, f := range et.Fields {
			set[f.Name] = true
		}
		documented[et.Type] = set
	}

	var violations []string
	root := filepath.Join("..", "..", "host")
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
		rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isRecorderEvent(lit.Type) {
				return true
			}
			typ := eventLiteralType(lit, nameToType)
			if typ == "" {
				return true // no resolvable Type key — a partial literal
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name == "Type" {
					continue
				}
				tag := fieldJSON[key.Name]
				if tag == "" {
					continue // not a tagged struct field (cannot happen for a compiling literal)
				}
				if common[tag] || documented[typ][tag] {
					continue
				}
				violations = append(violations, typ+"."+tag+" written at "+
					rel+":"+itoaLine(fset, kv.Pos())+" is documented nowhere in schema.go")
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("the host writes fields the schema does not describe, so the generated reference "+
			"omits them:\n  %s\n\nadd a row to the type's Fields in schema.go (or agentField() for `agent`)",
			strings.Join(violations, "\n  "))
	}
}

// isRecorderEvent reports whether a composite literal's type is recorder.Event
// (and not, say, recorder.EvError, which appears nested inside one).
func isRecorderEvent(typ ast.Expr) bool {
	sel, ok := typ.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Event" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "recorder"
}

// eventLiteralType resolves the type string an Event literal is for, from its
// Type key's recorder.Type* constant. "" when the literal sets no Type, or sets
// it to something other than a package Type* constant.
func eventLiteralType(lit *ast.CompositeLit, nameToType map[string]string) string {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Type" {
			continue
		}
		sel, ok := kv.Value.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		return nameToType[sel.Sel.Name]
	}
	return ""
}

func itoaLine(fset *token.FileSet, pos token.Pos) string {
	return strconv.Itoa(fset.Position(pos).Line)
}
