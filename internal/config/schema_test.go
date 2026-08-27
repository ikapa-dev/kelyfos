package config

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The schema in schema.go is what the generated reference is built from, so it
// has to agree with the parser in both directions. Neither direction is
// checkable by reading: one needs the parser run, and the other needs the
// parser's own source read. Both are cheap, and a reference that disagrees with
// the file it describes is the failure F-D4 exists to prevent.

// sectionHeader writes the lines that have to come before a key for its section
// to exist at all. An array-of-tables key needs its element opened first.
func sectionHeader(section string) string {
	switch section {
	case "":
		return ""
	case "resources", "sessions", "mcp", "team", "team.resources", "team.store":
		return "[" + section + "]\n"
	case "plugin":
		return "[[plugin]]\n"
	case "forward":
		return "[[forward]]\n"
	case "team.agent", "team.edge", "team.store.key":
		return "[[" + section + "]]\n"
	case "team.agent.resources", "team.agent.spawn", "team.agent.spawn.resources":
		return "[[team.agent]]\n[" + section + "]\n"
	}
	panic("schema_test: no header known for section " + section)
}

// Direction one: every key the reference documents is a key the parser takes,
// with the sample value the reference will print.
func TestSchemaKeysAllParse(t *testing.T) {
	dir := t.TempDir()
	for _, k := range Schema() {
		k := k
		t.Run(k.Section+"/"+k.Name, func(t *testing.T) {
			if k.Sample == "" {
				t.Fatalf("schema row %s.%s has no sample value; the reference cannot show it "+
					"and this test cannot check it", k.Section, k.Name)
			}
			path := filepath.Join(dir, strings.ReplaceAll(k.Section, ".", "_")+"_"+k.Name+".toml")
			body := sectionHeader(k.Section) + k.Name + " = " + k.Sample + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			switch {
			case k.Refused != "":
				if err == nil {
					t.Fatalf("%s is documented as refused and the parser accepted it", k.Name)
				}
				if !strings.Contains(err.Error(), k.Refused) {
					t.Errorf("the refusal does not say what the reference says it says\n"+
						"reference: %s\nparser:    %v", k.Refused, err)
				}
			default:
				// RefusedLater keys parse here on purpose: they are refused
				// before boot, which is a different thing and is said so.
				if err != nil {
					t.Fatalf("documented key %s = %s does not parse: %v", k.Name, k.Sample, err)
				}
			}
		})
	}
}

// Direction two: every key the parser takes is a key the reference documents.
//
// The parser is a switch over string literals, so the only honest way to
// enumerate it is to read it. This walks every `case "…"` in this package that
// sits inside one of the functions that assign keys, and fails on any literal
// with no schema row. Adding a key therefore fails this test until it is
// documented, which is the whole point.
func TestSchemaCoversTheParser(t *testing.T) {
	documented := map[string]bool{}
	for _, k := range Schema() {
		documented[k.Name] = true
	}
	// Header names are matched by the section switch, not by the key switch,
	// and are described by Sections() instead.
	for _, s := range Sections() {
		documented[s.Name] = true
	}

	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Only the functions that decide what a key means. A `case` anywhere else —
	// parseBool's "true"/"false", stripComment's quoting — says nothing about
	// the file's schema.
	//
	// The list is checked rather than trusted: TestEveryKeyFunctionIsScanned
	// below finds the ones this misses, because a new section's function added
	// to the parser and forgotten here would make this whole test pass by not
	// looking (E4-6).
	keyFuncs := map[string]bool{
		"parse": true, "teamKey": true, "assignResources": true, "pluginKey": true,
		"forwardKey": true,
	}

	var missing []string
	for _, f := range pkg {
		for name, file := range f.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || !keyFuncs[fn.Name.Name] {
					return true
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					cc, ok := n.(*ast.CaseClause)
					if !ok {
						return true
					}
					for _, e := range cc.List {
						lit, ok := e.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, err := strconv.Unquote(lit.Value)
						if err != nil || documented[v] {
							continue
						}
						missing = append(missing, fmt.Sprintf("%s: %q in %s",
							filepath.Base(name), v, fn.Name.Name))
					}
					return true
				})
				return true
			})
		}
	}
	if len(missing) > 0 {
		t.Errorf("the parser understands these and the schema does not, so the generated "+
			"reference would not mention them:\n  %s\n\nadd a row to Schema() in schema.go, "+
			"or to Sections() if it is a table header", strings.Join(missing, "\n  "))
	}
}

// The sections a key can be written under have to be the sections the header
// parser accepts, or a documented key would be unreachable.
func TestSchemaSectionsAllExist(t *testing.T) {
	dir := t.TempDir()
	for _, s := range Sections() {
		if s.Name == "" {
			continue
		}
		path := filepath.Join(dir, strings.ReplaceAll(s.Name, ".", "_")+".toml")
		if err := os.WriteFile(path, []byte(sectionHeader(s.Name)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Errorf("documented section %s is refused by the parser: %v", s.Header, err)
		}
	}
}

// Every accepted key has to be reachable from the section's own error message,
// because that message is what makes the schema load-bearing rather than
// decorative.
func TestUnknownKeyNamesTheRealKeys(t *testing.T) {
	dir := t.TempDir()
	for _, s := range Sections() {
		hint := knownKeys(s.Name)
		if hint == "" {
			continue
		}
		path := filepath.Join(dir, strings.ReplaceAll(s.Name, ".", "_")+"_typo.toml")
		body := sectionHeader(s.Name) + "definitely_not_a_key = 1\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil {
			t.Fatalf("%s: a bogus key was accepted", s.Header)
		}
		for _, k := range KeysIn(s.Name) {
			if !k.Accepted() && k.RefusedLater == "" {
				continue
			}
			if !strings.Contains(err.Error(), k.Name) {
				t.Errorf("%s: the unknown-key error does not mention %q:\n%v", s.Header, k.Name, err)
			}
		}
	}
}

// keyFunctions returns every function in this package that ends a switch with
// unknownKey — which is exactly the set of functions that decide what a key
// means, because that call is what a key-dispatching switch does with a key it
// does not recognise.
func keyFunctions(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go") && fi.Name() != "schema.go"
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, f := range pkg {
		for _, file := range f.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					id, ok := call.Fun.(*ast.Ident)
					if !ok {
						return true
					}
					// Either the helper or the thin wrapper over it. The two
					// wrappers themselves are not key functions: calling it is
					// all they do.
					if (id.Name == "unknownKey" || id.Name == "unknown") &&
						fn.Name.Name != "unknown" && fn.Name.Name != "unknownKey" {
						found[fn.Name.Name] = true
					}
					return true
				})
				return true
			})
		}
	}
	return found
}

// The direction-two test above scans a named list of functions. A list is a
// thing that goes out of date silently: a new section brings a new function,
// the function is not in the list, and the test that exists to catch
// undocumented keys passes because it never looked at them. This checks the
// list against the parser itself.
func TestEveryKeyFunctionIsScanned(t *testing.T) {
	scanned := map[string]bool{
		"parse": true, "teamKey": true, "assignResources": true, "pluginKey": true,
		"forwardKey": true,
	}
	for name := range keyFunctions(t) {
		if !scanned[name] {
			t.Errorf("%s decides what a key means and TestSchemaCoversTheParser does not read it; "+
				"add it to keyFuncs there and to the list in this test", name)
		}
	}
	for name := range scanned {
		if !keyFunctions(t)[name] {
			t.Errorf("%s is listed as a key function and no longer dispatches keys; remove it", name)
		}
	}
}
