package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
)

// P7-17/F21, the verification round: the gate was not on every door.
//
// loadPolicyAt's own comment said "every door in this CLI reaches a policy file
// through here". Two did not. serve-mcp's resolvePolicy and sessions.go's
// frozenPolicy each called config.Load themselves, with no config.Trust in
// front of either — and serve-mcp is not an obscure door, it is *the* door:
// `kelyfos connect` writes `serve-mcp --policy <abs>` into every client
// configuration it touches, so the path most users enter by was the one with no
// ownership or writability check on it.
//
// The tests below are in two halves, deliberately. Three drive the doors and
// say what they now refuse; two are structural, and pin the property that made
// the finding possible in the first place — that there was more than one place
// a policy could be read.

// worldWritablePolicy writes a policy file anybody on the machine can rewrite,
// which is what config.Trust refuses whether the file was discovered or named.
func worldWritablePolicy(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(path, []byte("[sandbox]\nimage = \"dev\"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	// os.WriteFile applies perm on creation only and the umask takes bits off
	// it, so the mode is set explicitly rather than hoped for.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	return path
}

// The door kelyfos connect points every client at.
func TestF21_ServeMCPsNamedPolicyGoesThroughTrust(t *testing.T) {
	path := worldWritablePolicy(t, t.TempDir())

	cfg, err := resolvePolicy(path)
	if err == nil {
		t.Fatalf("serve-mcp --policy loaded a policy every user on this machine can rewrite: %+v", cfg)
	}
	for _, want := range []string{path, "chmod"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// The frozen copy a resume runs under. It is written 0600 by `pause` under the
// cache root, so this is the writability half rather than the ownership one —
// and it is the file that decides the ceiling the resumed machine gets.
func TestF21_AFrozenPolicyGoesThroughTrust(t *testing.T) {
	dir := t.TempDir()
	worldWritablePolicy(t, dir)

	cfg, err := frozenPolicy(dir)
	if err == nil {
		t.Fatalf("a frozen policy every user on this machine can rewrite was loaded: %+v", cfg)
	}
	if !strings.Contains(err.Error(), "chmod") {
		t.Errorf("the refusal does not carry config.Trust's own message:\n%v", err)
	}
}

// A refusal has to stop the operation. `resume` read the current policy as
// `current, _ := loadPolicy()`, so a policy this user is not allowed to trust
// became a nil `current` — and frozenFitsCurrent returns at its first line when
// current is nil, which means the frozen ceiling was applied with nothing
// checking it against the project's own.
//
// Driven end to end through resumeCmd rather than asserted about the line,
// against a session whose snapshot says it had egress: that refusal is the next
// thing resume does, so on the parent this test sees *that* message and on the
// branch it sees the policy one. No microVM is involved either way.
func TestF21_AResumeStopsOnAPolicyItCannotTrust(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("KELYFOS_CACHE", cache)

	dir := filepath.Join(cache, "named", "paused-one")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(NamedMeta{Name: "paused-one", Sandbox: "deadbeef", Session: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "named.json"), append(meta, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	// has_network is what resume refuses immediately after the policy check.
	if err := os.WriteFile(filepath.Join(dir, "meta.json"),
		[]byte(`{"arch":"aarch64","flavor":"dev","has_network":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	path := worldWritablePolicy(t, project)
	f21Chdir(t, project)

	err = resumeCmd([]string{"paused-one"})
	if err == nil {
		t.Fatal("the resume ran under a policy it is not allowed to trust")
	}
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("the resume did not stop on the policy refusal; it got as far as:\n%v", err)
	}
}

// A workspace an agent names is packed into its guest and written back over
// that host directory when the team comes down. `kelyfos run` has refused an
// out-of-tree one since F21; this door did not, so the same file that could not
// name a directory outside its own tree as [sandbox] workspace could still name
// it as [[team.agent]] workspace.
func TestF21_ATeamAgentWorkspaceOutsideThePolicysTreeIsRefused(t *testing.T) {
	project := t.TempDir()
	outside := t.TempDir()

	body := "[team]\nname = \"t\"\n\n[[team.agent]]\nname = \"one\"\nworkspace = " +
		strconv.Quote(outside) + "\n"
	path := filepath.Join(project, config.FileName)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the test's own policy does not parse: %v", err)
	}

	plan, err := planTeam(cfg)
	if err == nil {
		t.Fatalf("an agent workspace outside the policy file's tree was planned: %+v", plan)
	}
	for _, want := range []string{"one", outside, project, "no --workspace flag"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// And the other direction, which the fix must not break: a workspace inside
	// the project is ordinary and still plans.
	inside := filepath.Join(project, "work")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	ok := "[team]\nname = \"t\"\n\n[[team.agent]]\nname = \"one\"\nworkspace = \"work\"\n"
	if err := os.WriteFile(path, []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := planTeam(cfg); err != nil {
		t.Errorf("an ordinary in-tree agent workspace was refused: %v", err)
	}
}

// A relative --policy is what somebody types, and it made every scope rule
// refuse an absolute path that was genuinely inside the project.
//
// filepath.Dir("kelyfos.toml") is ".", and insideTree then asks
// filepath.Rel(".", "/abs/path"), which errors and answers "outside". Found by
// the A1 review by running the binary rather than reading it: the false
// refusal is fail-closed, so no test noticed, and the message rendered the
// project root as "." — which tells a reader nothing (P7-17/A1, review round).
//
// All three scope rules, because one answer to "which tree is this file's" is
// the point of policyTreeRoot.
func TestF21_ARelativePolicyPathStillKnowsItsOwnTree(t *testing.T) {
	project := t.TempDir()
	inside := filepath.Join(project, "ws")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	f21Chdir(t, project)

	// The relative spelling and the absolute one have to agree, on a workspace
	// that is inside the tree either way.
	for _, policyPath := range []string{config.FileName, filepath.Join(project, config.FileName)} {
		if err := checkWorkspaceScope(policyPath, inside); err != nil {
			t.Errorf("--policy %s refused a workspace inside its own project: %v", policyPath, err)
		}
		if err := checkAgentWorkspaceScope(policyPath, 7, "one", inside); err != nil {
			t.Errorf("--policy %s refused an agent workspace inside its own project: %v",
				policyPath, err)
		}
	}

	// And the refusal still fires for something genuinely outside, with the
	// project named as a path rather than as ".".
	outside := t.TempDir()
	err := checkAgentWorkspaceScope(config.FileName, 7, "one", outside)
	if err == nil {
		t.Fatal("an out-of-tree agent workspace was accepted under a relative --policy")
	}
	if strings.Contains(err.Error(), "outside .") {
		t.Errorf("the refusal renders the project root as \".\", which names nothing:\n%v", err)
	}
	if !strings.Contains(err.Error(), project) {
		t.Errorf("the refusal does not name the project directory:\n%v", err)
	}
	// And it names the line it was written on, which is what every other
	// team-plan refusal does and what docs/reference/denials.md says they do.
	if !strings.Contains(err.Error(), ":7:") {
		t.Errorf("the refusal does not name the line the agent was declared on:\n%v", err)
	}
}

// ---- the structural half -------------------------------------------------

// repoFiles walks every non-test Go file in the repository.
//
// The whole repository rather than this package, because the finding was that a
// second reader existed: a rule that only looks where the rule is already kept
// cannot find the file that does not keep it.
func repoFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "dist", "bin", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 50 {
		t.Fatalf("only %d non-test Go files were walked; this repository has hundreds, "+
			"so the walk is looking in the wrong place and would pass on anything", len(out))
	}
	return out
}

// configLocalName is what `internal/config` is called in this file: its package
// name, an import alias, or "." for a dot-import.
//
// The first version of the walk below assumed "config" and nothing else, and the
// A1 review walked around it four ways in one file — an aliased import, the
// function taken through a variable, a package-level `var`, and a package-level
// func literal — with the test still green. A spelling check is not a property.
// The alias is read from the file's own import block now, so the walk follows
// whatever name the file chose.
func configLocalName(f *ast.File) (string, bool) {
	const path = `"github.com/ikapa-dev/kelyfos/internal/config"`
	for _, imp := range f.Imports {
		if imp.Path.Value != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name, true
		}
		return "config", true
	}
	return "", false
}

// config.Load is the read with no check in front of it. Exactly one function
// may mention it, and this says which.
//
// MENTION, not call. The review took the function through a variable
// (`load := cfgpkg.Load; load(p)`) and the call-shaped walk saw nothing, which
// is right — the call site is `load(p)` and there is no selector there. So the
// rule is now about the identifier reaching anywhere outside the gate at all,
// which is the property the sentence claims.
//
// WHAT IT STILL CANNOT SEE, stated because the first version of this comment
// implied it saw everything: a policy read through `os.ReadFile` and a TOML
// parser somebody writes by hand, reflection, `go:linkname`, or a second copy
// of `internal/config` under another import path. No syntactic rule reaches
// those. What it does cover is every way of naming this function that compiles
// — plain, aliased, dot-imported, called, assigned, or referenced at package
// level.
func TestF21_NothingLoadsAPolicyOutsideTheGate(t *testing.T) {
	const gate = "loadPolicyAt"
	seenGate := false
	for _, file := range repoFiles(t) {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		local, imported := configLocalName(f)
		if !imported {
			continue
		}
		// The enclosing function for each position, so a mention can be
		// attributed. Package-level declarations have none, which is itself
		// worth reporting: a `var _, _ = config.Load(p)` runs before main.
		type span struct {
			name       string
			start, end token.Pos
		}
		var funcs []span
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				funcs = append(funcs, span{fn.Name.Name, fn.Pos(), fn.End()})
			}
		}
		enclosing := func(p token.Pos) string {
			for _, fn := range funcs {
				if p >= fn.start && p < fn.end {
					return fn.name
				}
			}
			return "package level"
		}

		report := func(pos token.Pos) {
			where := enclosing(pos)
			if where == gate {
				seenGate = true
				return
			}
			t.Errorf("%s:%d: %s mentions config.Load.\n"+
				"  %s is the only function allowed to, because it is the only one that calls\n"+
				"  config.Trust first. A second reader is how serve-mcp — the door\n"+
				"  `kelyfos connect` writes into every client configuration — ended up with no\n"+
				"  ownership or writability check at all (P7-17/F21).",
				file, fset.Position(pos).Line, where, gate)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				// pkg.Load, however pkg is spelled in this file.
				if v.Sel.Name != "Load" {
					return true
				}
				if id, ok := v.X.(*ast.Ident); ok && id.Name == local {
					report(v.Pos())
				}
			case *ast.Ident:
				// A dot-import puts Load in this file's own scope. Only then,
				// because "Load" is an ordinary name otherwise.
				if local == "." && v.Name == "Load" {
					report(v.Pos())
				}
			}
			return true
		})
	}
	// And the gate itself has to still be doing the reading. Moving the Load
	// somewhere this walk cannot see would otherwise satisfy the rule by
	// emptying it.
	if !seenGate {
		t.Errorf("no mention of config.Load was found inside %s at all; either it stopped "+
			"reading the file or this walk no longer sees it", gate)
	}
}

// A refusal that is discarded is a refusal that did not happen.
//
// Two shapes are refused, and they are the two this CLI actually had: `_` for
// the error, and the call as an if-statement initialiser whose condition tests
// `err == nil`, so the refusal becomes a branch not taken rather than a return.
//
// The first version banned EVERY if-statement initialiser, which the A1 review
// showed also refuses the ordinary correct idiom
// `if cfg, err := loadPolicy(); err != nil { return err } else if cfg != nil`.
// A guard that fails on correct code is a guard somebody deletes.
//
// WHAT IT CANNOT SEE, and this is the honest half: `_ = err` written later in
// the function, `if err != nil { return nil }`, and a package-level `var`. Each
// needs flow analysis rather than a shape rule, and a shape rule that pretends
// otherwise is the fourteenth test on this task that could not fail. The
// blank-identifier and `err == nil` forms are what was actually written here
// twice, which is what a regression guard is for.
func TestF21_NoDoorSwallowsAPolicyRefusal(t *testing.T) {
	loaders := map[string]bool{"loadPolicy": true, "loadPolicyAt": true}
	calls := 0

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		calls += swallowedPolicyLoads(t, fset, f, file, loaders)
	}
	// Eight doors call one of these. A rule that stopped finding any of them
	// would pass silently, which is the failure this whole review round is
	// about.
	if calls < 6 {
		t.Errorf("only %d calls to loadPolicy/loadPolicyAt were found; this package has "+
			"eight or so. The walk is looking in the wrong place.", calls)
	}
}

func swallowedPolicyLoads(t *testing.T, fset *token.FileSet, f *ast.File, file string, loaders map[string]bool) int {
	t.Helper()
	calls := 0
	// The if-statements whose initialiser is an assignment, mapped to the
	// condition, so the condition can be read rather than the shape assumed.
	inIfInit := map[ast.Node]ast.Expr{}
	ast.Inspect(f, func(n ast.Node) bool {
		if ifs, ok := n.(*ast.IfStmt); ok && ifs.Init != nil {
			inIfInit[ifs.Init] = ifs.Cond
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok || !loaders[name.Name] {
			return true
		}
		calls++
		where := fset.Position(as.Pos())
		if len(as.Lhs) != 2 {
			return true
		}
		if id, ok := as.Lhs[1].(*ast.Ident); ok && id.Name == "_" {
			t.Errorf("%s:%d: the error from %s is discarded.\n"+
				"  A policy this user is not allowed to trust then reads as \"no policy\", and every\n"+
				"  ceiling check downstream is skipped rather than enforced (P7-17/F21).",
				file, where.Line, name.Name)
		}
		if cond, isInit := inIfInit[ast.Stmt(as)]; isInit && testsErrIsNil(cond) {
			t.Errorf("%s:%d: %s is called in an if-statement initialiser whose condition tests "+
				"that the error is nil, so a refusal is a branch not taken rather than a return.\n"+
				"  `if cfg, err := loadPolicy(); err == nil && cfg != nil` is how `kelyfos "+
				"sessions pause`\n  silently froze nothing when the policy was refused "+
				"(P7-17/F21).",
				file, where.Line, name.Name)
		}
		return true
	})
	return calls
}

// testsErrIsNil reports whether an expression contains `<something> == nil`.
// The name of the error variable is deliberately not required to be `err`: what
// makes the shape a swallow is that the nil case is the one the body runs for.
func testsErrIsNil(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || bin.Op != token.EQL {
			return true
		}
		if id, ok := bin.Y.(*ast.Ident); ok && id.Name == "nil" {
			found = true
		}
		return true
	})
	return found
}
