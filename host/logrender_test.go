package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every event type the recorder can write has a line `kelyfos log` can print.
//
// printEvent's default arm exists for a chain written by a NEWER kelyfos and
// replayed by an older one, which docs/events.md §3 says is supported: the raw
// line, through the sanitiser. It is not meant to be reached by an event type
// this build knows perfectly well how to write.
//
// It was. Five of thirty-one — session.policy, team.topology, session.erasure,
// secret.withheld and secret.scrubbed — had no arm, so `kelyfos log` printed a
// whole JSON object in the middle of a text transcript. All five were added
// after the renderer was written, and nothing connected the two: adding an
// event type and rendering it are separate edits in separate files, and the
// first is the one a task remembers. dev/accept-runs.sh caught it only
// indirectly, by asserting the live tail carries no `{`.
//
// So the check is here rather than in a shell script, and it is structural: a
// new Type constant fails this test until somebody decides how it reads. That
// is the same shape as tools/gendocs' TestEveryDocumentUnderDocsIsInTheLLMsSet
// and for the same reason — the cost of forgetting is paid by the person
// adding the thing, not by a reader months later.
func TestEveryRecordedEventTypeHasARenderer(t *testing.T) {
	types := recorderEventTypes(t)
	if len(types) < 20 {
		t.Fatalf("only found %d event types; the parse is looking in the wrong place", len(types))
	}
	rendered := renderedEventTypes(t)

	// Deliberate omissions go here with a reason. Empty on purpose.
	omitted := map[string]string{}

	var missing []string
	for konst, wire := range types {
		if rendered[konst] || omitted[konst] != "" {
			continue
		}
		missing = append(missing, konst+" ("+wire+")")
	}
	if len(missing) > 0 {
		t.Errorf("these event types have no arm in printEvent, so `kelyfos log` prints them "+
			"as a raw JSON line in the middle of a text transcript:\n  %s\n"+
			"Add a case to host/log.go, or list it in `omitted` above with the reason.",
			strings.Join(missing, "\n  "))
	}
}

// recorderEventTypes reads the constants rather than a list kept by hand: the
// list kept by hand is the thing that went out of date.
func recorderEventTypes(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	files, err := filepath.Glob(filepath.Join("..", "internal", "recorder", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^(Type[A-Za-z0-9]+)$`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !re.MatchString(name.Name) || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					wire := strings.Trim(lit.Value, `"`)
					// An event type is a dotted wire name; Source* and Reason*
					// constants share the Type prefix in neither case, but a
					// bare word would be one of those if one ever did.
					if strings.Contains(wire, ".") {
						out[name.Name] = wire
					}
				}
			}
		}
	}
	return out
}

// renderedEventTypes collects every recorder.TypeX named on a `case` in
// host/log.go — including the second and third of a comma-separated arm, which
// is where team.refused lives and which a naive grep misses.
func renderedEventTypes(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("log.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "log.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expr := range cc.List {
			sel, ok := expr.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "recorder" {
				out[sel.Sel.Name] = true
			}
		}
		return true
	})
	return out
}
