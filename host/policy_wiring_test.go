package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Every place that records a machine's posture must also record its policy
// (P7-2, docs/policy-record.md §4, §9.3).
//
// WithPosture's call sites are docs/policy-record.md §4's own definition of
// "a door that opens a chain with a machine in it" — audited there against
// the current source and cross-checked against recorder.TypeSessionStart,
// rather than assumed. A ninth call site, the serve-mcp audit chain
// (host/servemcpaudit.go's openAudit), writes session.start with no machine
// behind it and correctly calls neither WithPosture nor NewSessionPolicy —
// it needs no exemption here because this test starts from WithPosture, not
// from session.start, and that chain never calls WithPosture at all.
//
// Scoped to the nearest enclosing function-LIKE node — a *ast.FuncDecl or a
// *ast.FuncLit — rather than to the file, unlike TestEveryFileThatBuildsA-
// ProxyWiresItsAudit's per-file rule. Per-function granularity is what this
// test needs to have caught the bug P7-2 itself found and fixed:
// broker.OnSpawn is a closure inside raiseTeam, and before P7-2 it called
// neither WithPosture nor NewSessionPolicy while raiseTeam's *outer* function
// body called both, elsewhere, for a different machine entirely. A per-file
// rule would have called that file wired and missed the closure that was not.
//
// Same shape as TestEveryFileThatBuildsAProxyWiresItsAudit and
// internal/config's TestEveryKeyFunctionIsScanned: read the source, do not
// trust a list.
func TestEveryWithPostureCallHasAMatchingSessionPolicy(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the host package: %v", err)
	}

	found := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			found += checkPolicyWiring(t, name, file)
		}
	}
	if found == 0 {
		t.Fatal("no WithPosture call found in the host package — this test is looking in the wrong place")
	}
}

// ownBodyCalls reports whether fn's own body — not a nested FuncDecl's or
// FuncLit's, which each get their own, separate check when the outer walk
// reaches them — contains a call satisfying match.
func ownBodyCalls(fn ast.Node, match func(*ast.CallExpr) bool) bool {
	found := false
	ast.Inspect(fn, func(inner ast.Node) bool {
		if found || inner == nil {
			return false
		}
		if inner != fn {
			switch inner.(type) {
			case *ast.FuncDecl, *ast.FuncLit:
				return false
			}
		}
		if call, ok := inner.(*ast.CallExpr); ok && match(call) {
			found = true
		}
		return true
	})
	return found
}

func policyCallsMethod(name string) func(*ast.CallExpr) bool {
	return func(c *ast.CallExpr) bool {
		sel, ok := c.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == name
	}
}

// callsAny is policyCallsMethod, generalised to more than one bare-identifier name
// as well — host/team.go's agentPolicyEvent is a plain function, not a
// method, and wraps exactly one recorder.NewSessionPolicy call, used
// identically by the declared-agent ready loop and by broker.OnSpawn. A call
// to it here is exactly as much wiring as a direct NewSessionPolicy call
// would be — and this test would still fail if agentPolicyEvent itself ever
// stopped calling NewSessionPolicy, because agentPolicyEvent's own FuncDecl
// is scanned like any other function and gets no special case.
func callsAny(method string, idents ...string) func(*ast.CallExpr) bool {
	return func(c *ast.CallExpr) bool {
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
			return true
		}
		if id, ok := c.Fun.(*ast.Ident); ok {
			for _, want := range idents {
				if id.Name == want {
					return true
				}
			}
		}
		return false
	}
}

// checkPolicyWiring walks one file's function-like nodes (FuncDecl and
// FuncLit alike) and reports an error for every one whose own body calls
// WithPosture but never NewSessionPolicy (or agentPolicyEvent, which wraps
// it). It returns how many WithPosture calls it found, so the caller can
// confirm it looked in the right place at all.
func checkPolicyWiring(t *testing.T, file string, f *ast.File) int {
	t.Helper()

	var funcs []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			funcs = append(funcs, n)
		}
		return true
	})

	n := 0
	for _, fn := range funcs {
		if !ownBodyCalls(fn, policyCallsMethod("WithPosture")) {
			continue
		}
		n++
		if !ownBodyCalls(fn, callsAny("NewSessionPolicy", "agentPolicyEvent")) {
			t.Errorf("%s: a function calls WithPosture (recording a machine's jailed/profile) "+
				"but never NewSessionPolicy (recording what it was permitted) in the same scope. "+
				"Every door that opens a chain with a machine in it needs both — "+
				"docs/policy-record.md §4, §9.3.", file)
		}
	}
	return n
}

// TestEverySessionStartSiteHasAMatchingSessionPolicy is docs/policy-record.md
// §9.3's own test, run as written there — starting from session.start —
// rather than only approximated by TestEveryWithPostureCallHasAMatchingSessionPolicy
// above, which starts from WithPosture instead.
//
// The two are not the same mechanism, on purpose (F3, the review that
// reopened P7-2). TestEveryWithPostureCallHasAMatchingSessionPolicy is
// mutation-tested and genuinely catches a door that calls WithPosture and
// then forgets NewSessionPolicy — including at per-closure granularity, the
// bug P7-2 itself found in broker.OnSpawn — but a door that never calls
// WithPosture at all is invisible to it *by construction*: there is nothing
// for that walk to start from. A hypothetical tenth door that appends
// TypeSessionStart and TypeSessionReady directly, with no WithPosture call
// anywhere, passes the WithPosture-based test silently — proven by the
// reviewer with exactly such a fixture. §9.3 asks for the walk to start from
// session.start instead, which is what this test does.
//
// It finds every recorder.Event composite literal whose Type field is
// recorder.TypeSessionStart, and requires the *enclosing top-level function*
// to REACH a call to recorder.NewSessionPolicy — directly, or transitively
// through any other function in the host package it calls, to any depth —
// rather than only calling it in its own lexical scope. Two shapes in the
// current source need that transitivity, not one:
//
//   - door 2 (`team up`, host/team.go's raiseTeam) writes exactly one
//     session.start and satisfies it with NewSessionPolicy calls made later,
//     once per agent, in a loop and inside the broker.OnSpawn closure defined
//     within that same function — reachable at depth 1, through
//     agentPolicyEvent.
//   - door 3 (`fork`, host/fork.go's forkCmd) writes session.start inside a
//     goroutine literal, and only reaches NewSessionPolicy two calls later:
//     forkCmd calls recordFork (a plain top-level function, named nothing
//     this test hardcodes), and recordFork calls NewSessionPolicy. This is
//     what caught the transitive-reachability requirement in the first
//     place: an earlier version of this test recognised only the literal
//     names "NewSessionPolicy" and "agentPolicyEvent" as evidence of wiring,
//     which is the exact hand-maintained-list shape F1 and F3 both found
//     wrong elsewhere in this phase, and it failed on forkCmd for exactly
//     that reason the first time this test ran for real. Reachability
//     through the package's actual call graph — reachesSessionPolicy below —
//     closes that the same way reflection closed it for clipLargestField:
//     a helper added next month, at any depth, is covered the day it lands.
//
// The one exemption is the literal that also sets Reason to
// recorder.ReasonServeMCP: docs/policy-record.md §4.1's ninth site, the
// serve-mcp audit chain, which legitimately has no machine behind it and so
// no session.policy to match.
//
// Kept alongside TestEveryWithPostureCallHasAMatchingSessionPolicy rather
// than replacing it — see D68 in PLAN.html's decision log for why running
// both, instead of §9.3's literal "one test," is the deliberate choice here.
func TestEverySessionStartSiteHasAMatchingSessionPolicy(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the host package: %v", err)
	}

	// Built once, across every non-test file in the package, before any site
	// is checked: recordFork lives in the same file as forkCmd here, but
	// nothing about this test should depend on that — a helper defined in a
	// different file of the same package has to be just as reachable.
	funcsByName := map[string]*ast.FuncDecl{}
	var files []struct {
		name string
		file *ast.File
	}
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			files = append(files, struct {
				name string
				file *ast.File
			}{name, file})
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
					funcsByName[fn.Name.Name] = fn
				}
			}
		}
	}

	sites := 0
	for _, f := range files {
		sites += checkSessionStartWiring(t, f.name, f.file, funcsByName)
	}
	if sites == 0 {
		t.Fatal("no session.start site (recorder.TypeSessionStart) found in the host package — this test is looking in the wrong place")
	}
}

// checkSessionStartWiring walks one file's top-level functions. For every one
// that appends a recorder.Event literal with Type: recorder.TypeSessionStart,
// it requires that same function to reach recorder.NewSessionPolicy —
// directly or transitively, per reachesSessionPolicy — unless the literal
// also carries Reason: recorder.ReasonServeMCP (docs/policy-record.md §4.1).
// It returns how many session.start sites it found, so the caller can
// confirm it looked in the right place at all.
func checkSessionStartWiring(t *testing.T, file string, f *ast.File, funcsByName map[string]*ast.FuncDecl) int {
	t.Helper()

	sites := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		var lits []*ast.CompositeLit
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.CompositeLit); ok && isSessionStartLiteral(lit) {
				lits = append(lits, lit)
			}
			return true
		})
		if len(lits) == 0 {
			continue
		}
		sites += len(lits)

		hasPolicy := reachesSessionPolicy(fn, funcsByName, map[string]bool{})
		for _, lit := range lits {
			if isServeMCPAuditLiteral(lit) {
				continue
			}
			if !hasPolicy {
				t.Errorf("%s: func %s appends session.start (recorder.TypeSessionStart) but never reaches "+
					"recorder.NewSessionPolicy — directly, or through any function it calls — every door that "+
					"opens a chain with a machine in it needs a matching session.policy (docs/policy-record.md "+
					"§4, §9.3), unless the same literal also carries Reason: recorder.ReasonServeMCP "+
					"(§4.1's audit-chain exemption)",
					file, fn.Name.Name)
			}
		}
	}
	return sites
}

// reachesSessionPolicy reports whether fn's body — including every nested
// closure, so a broker.OnSpawn-shaped FuncLit is covered without a special
// case — calls recorder.NewSessionPolicy, either directly or by calling
// another function defined in the host package that itself (transitively)
// does. visited guards against infinite recursion on a call cycle and is
// shared across the whole search from one session.start site, keyed by
// function name.
func reachesSessionPolicy(fn ast.Node, funcsByName map[string]*ast.FuncDecl, visited map[string]bool) bool {
	found := false
	var next []string
	ast.Inspect(fn, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call)
		if name == "NewSessionPolicy" {
			found = true
			return false
		}
		if name != "" && !visited[name] {
			next = append(next, name)
		}
		return true
	})
	if found {
		return true
	}
	for _, name := range next {
		if visited[name] {
			continue
		}
		visited[name] = true
		callee, ok := funcsByName[name]
		if !ok {
			continue // not a function this package defines — nothing to recurse into
		}
		if reachesSessionPolicy(callee, funcsByName, visited) {
			return true
		}
	}
	return false
}

// calleeName returns the simple name a call expression invokes — the bare
// identifier for a plain function call, or the selector's own name for a
// method call or a package-qualified call like recorder.NewSessionPolicy
// (the package qualifier itself is dropped, the same way callsAny already
// treats it elsewhere in this file). Anything else (a call through a value,
// e.g. a func-typed field or variable) returns "", which reachesSessionPolicy
// treats as a dead end rather than a false match.
func calleeName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	default:
		return ""
	}
}

// isSessionStartLiteral reports whether lit is a recorder.Event composite
// literal whose Type field is set to recorder.TypeSessionStart.
func isSessionStartLiteral(lit *ast.CompositeLit) bool {
	if !isRecorderEventLiteral(lit) {
		return false
	}
	return fieldIsRecorderSelector(lit, "Type", "TypeSessionStart")
}

// isServeMCPAuditLiteral reports whether lit's Reason field is
// recorder.ReasonServeMCP — docs/policy-record.md §4.1's exemption from
// needing a matching session.policy.
func isServeMCPAuditLiteral(lit *ast.CompositeLit) bool {
	return fieldIsRecorderSelector(lit, "Reason", "ReasonServeMCP")
}

// isRecorderEventLiteral reports whether lit is written as recorder.Event{...}.
func isRecorderEventLiteral(lit *ast.CompositeLit) bool {
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Event" {
		return false
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	return ok && pkgIdent.Name == "recorder"
}

// fieldIsRecorderSelector reports whether lit has a key: value entry named
// key whose value is the selector recorder.want.
func fieldIsRecorderSelector(lit *ast.CompositeLit, key, want string) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != key {
			continue
		}
		sel, ok := kv.Value.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != want {
			return false
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		return ok && pkgIdent.Name == "recorder"
	}
	return false
}
