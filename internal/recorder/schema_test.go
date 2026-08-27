package recorder

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// typeConstants returns every Type* constant this package's own source
// declares, string value -> constant name, by parsing the source rather than
// trusting a hand-maintained list of names. Shared by TestSchemaCoversEveryType
// and TestSchemaDescribesNothingExtra below, which check the same fact from
// opposite directions, so neither can drift from what the const block
// actually declares the way TestSchemaDescribesNothingExtra's own list once
// could: it went stale the moment P7-3 added TypeTeamTopology, silently,
// until this test's next run caught it — proof of exactly the failure mode a
// hand-maintained list keeps producing everywhere in this codebase (F1, F3),
// closed here the same way those were: read the source, do not trust a list.
func typeConstants(t *testing.T) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]string{}
	for _, f := range pkg {
		for _, file := range f.Files {
			for _, d := range file.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
						continue
					}
					if !strings.HasPrefix(vs.Names[0].Name, "Type") {
						continue
					}
					lit, ok := vs.Values[0].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					if v, err := strconv.Unquote(lit.Value); err == nil {
						out[v] = vs.Names[0].Name
					}
				}
			}
		}
	}
	return out
}

// Every Type* constant has to have a schema row, or the generated reference
// would silently omit an event a consumer will meet.
func TestSchemaCoversEveryType(t *testing.T) {
	described := map[string]bool{}
	for _, e := range Types() {
		described[e.Type] = true
	}

	var missing []string
	for v, name := range typeConstants(t) {
		if !described[v] {
			missing = append(missing, name+" = "+v)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these event types are written and undescribed, so the generated "+
			"reference would not mention them:\n  %s\n\nadd a row to Types() in schema.go",
			strings.Join(missing, "\n  "))
	}
}

// The reverse: a described type that no constant defines would document an event
// nothing can ever write.
func TestSchemaDescribesNothingExtra(t *testing.T) {
	real := typeConstants(t)
	for _, e := range Types() {
		if _, ok := real[e.Type]; !ok {
			t.Errorf("schema describes %q, which no Type* constant defines", e.Type)
		}
	}
}

// Every field name in the schema has to be a real json tag on Event, or the
// reference would name a key that never appears in a file.
func TestSchemaFieldsExist(t *testing.T) {
	tags := map[string]bool{}
	rt := reflect.TypeOf(Event{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if name, _, _ := strings.Cut(tag, ","); name != "" && name != "-" {
			tags[name] = true
		}
	}
	for _, e := range Types() {
		for _, f := range e.Fields {
			if !tags[f.Name] {
				t.Errorf("%s documents a field %q that Event has no json tag for", e.Type, f.Name)
			}
		}
	}
	for _, f := range CommonFields() {
		if !tags[f.Name] {
			t.Errorf("the common-field list names %q, which Event has no json tag for", f.Name)
		}
	}
}

// The common fields are the canonical hash prefix, so their order is not a
// presentation choice: it is the order an independent verifier must serialize
// in. Pin it against the struct rather than against a reader's memory.
func TestCommonFieldsAreTheStructPrefix(t *testing.T) {
	rt := reflect.TypeOf(Event{})
	common := CommonFields()
	if rt.NumField() < len(common) {
		t.Fatalf("Event has %d fields, fewer than the %d common ones", rt.NumField(), len(common))
	}
	for i, f := range common {
		name, _, _ := strings.Cut(rt.Field(i).Tag.Get("json"), ",")
		if name != f.Name {
			t.Errorf("common field %d is %q in the schema and %q in the struct — "+
				"the hash order and the documented order have diverged", i, f.Name, name)
		}
	}
}
