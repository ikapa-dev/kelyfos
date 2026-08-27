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
