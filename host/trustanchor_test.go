package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// A boot that hands the guest the run's CA anchor must still be able to stop
// the machine when the guest says no.
//
// This is the guard for a bug that had already shipped. InstallTrustAnchor is
// the last thing a networked boot does, and it is the only step in a boot whose
// answer comes from the guest: it fails on a refusal (`!resp.OK`), which the
// thing inside the machine decides. By the time it runs the VM is up and
// running. Three of the six call sites returned that error without stopping it
// — the shim's boot, serve-mcp's boot, and `snapshot restore`, whose shutdown
// defer was registered one block too late — so an untrusted guest could, at
// will, hand the host a Firecracker process it no longer had a handle on. The
// VMM is started in its own process group with no Pdeathsig, so on the CLI path
// it outlived `kelyfos restore` itself; on the two server paths the box never
// reached the map that teardown walks, so nothing could stop it and the census
// that bounds how many machines a door may hold under-counted it for the life
// of the process.
//
// Nothing caught it because every door writes its own unwind. Two of the three
// leaking sites already owned a correct close() and had a failure defer beside
// it that hand-rolled a strict subset of one — proxy, network, cgroup, recorder
// and no machine — which is the shape a reader skims past.
//
// The rule is per call site rather than per file, because host/team.go holds a
// site that gets it right and, until this test, held nothing that would notice
// if a second one appeared that did not. Two ways of satisfying it are
// accepted, because both are in the tree and both are correct: stop the machine
// in the branch that handles the refusal, or register a teardown for it before
// the anchor is offered. What is not accepted is a bare return.
//
// It reads ../shim as well as this package on purpose. The invariant is one
// invariant and it is the per-package list that missed sites the last time.
// Same shape as TestEveryFileThatBuildsAProxyWiresItsAudit: read the source, do
// not trust a list.
func TestEveryBootThatInstallsATrustAnchorCanStopTheMachineWhenItIsRefused(t *testing.T) {
	checked := 0
	for _, dir := range []string{".", "../shim"} {
		fset := token.NewFileSet()
		pkgs, err := parser.ParseDir(fset, dir, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", dir, err)
		}

		files := map[string]*ast.File{}
		// Every method this package declares, so a teardown reached through one
		// — serve-mcp's b.close, the shim's b.close — can be followed one level
		// to see whether it really stops a machine. Keyed by name only, because
		// there is no type information here; a package holding two methods of
		// one name is answered by "does any of them stop a machine", which is
		// looser than ideal and still refuses every shape this test exists to
		// refuse.
		methods := map[string][]*ast.FuncDecl{}
		for _, pkg := range pkgs {
			for name, f := range pkg.Files {
				if strings.HasSuffix(name, "_test.go") {
					continue
				}
				files[name] = f
				for _, decl := range f.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
						methods[fn.Name.Name] = append(methods[fn.Name.Name], fn)
					}
				}
			}
		}

		for _, f := range files {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				for _, guard := range trustAnchorGuards(fn) {
					checked++
					if reapsAMachine(guard.Body, methods) {
						continue
					}
					if deferredReaperBefore(fn, guard.Pos(), methods) {
						continue
					}
					t.Errorf("%s (%s) installs a trust anchor and returns its refusal without "+
						"stopping the machine: the guest decides that answer, and the VM is already "+
						"running by then. Shut it down on that branch, or register a teardown for it "+
						"before the anchor is offered.",
						fn.Name.Name, fset.Position(guard.Pos()))
				}
			}
		}
	}
	// Six when this was written: run.go, team.go, servemcpstate.go,
	// servemcptools.go, snapshot.go and shim.go. The count is deliberately not
	// pinned — the thing worth failing on is a site that leaks, not a site that
	// moved.
	if checked == 0 {
		t.Fatal("no InstallTrustAnchor call site found — this test is looking in the wrong place")
	}
}

// trustAnchorGuards finds every `if err := x.InstallTrustAnchor(…); err != nil`
// in one function. The whole tree spells it that way; a site that spells it
// some other way will not be found here and should extend this rather than be
// left unchecked.
func trustAnchorGuards(fn *ast.FuncDecl) []*ast.IfStmt {
	var out []*ast.IfStmt
	ast.Inspect(fn, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || ifs.Init == nil {
			return true
		}
		if callsMethod(ifs.Init, "InstallTrustAnchor") {
			out = append(out, ifs)
		}
		return true
	})
	return out
}

// deferredReaperBefore reports whether the function registers a teardown that
// stops the machine, at a point the anchor call would already have passed. The
// position matters and is the whole of `snapshot restore`'s bug: the shutdown
// defer was there, one block below the return that needed it.
func deferredReaperBefore(fn *ast.FuncDecl, pos token.Pos, methods map[string][]*ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		d, ok := n.(*ast.DeferStmt)
		if !ok || d.Pos() > pos {
			return true
		}
		if reapsAMachine(d, methods) {
			found = true
		}
		return true
	})
	return found
}

// reapsAMachine reports whether this fragment stops a sandbox: a Shutdown of
// its own, or a call to one of this package's methods that does.
func reapsAMachine(n ast.Node, methods map[string][]*ast.FuncDecl) bool {
	if callsMethod(n, "Shutdown") {
		return true
	}
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		for _, m := range methods[sel.Sel.Name] {
			if m.Body != nil && callsMethod(m.Body, "Shutdown") {
				found = true
			}
		}
		return true
	})
	return found
}

func callsMethod(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			found = true
		}
		return true
	})
	return found
}
