package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestSnapshotRestoreWiresAuditBeforeResume is a regression test for the
// window a restored sandbox's proxy audit hooks used to sit unwired across.
//
// sandbox.Restore does not merely build a Sandbox value and hand it back: it
// calls the Firecracker resume API partway through, and the guest is live —
// making its own round trips over the control port (Resync, confirmSeccomp) —
// well before Restore returns to snapshotRestore. This function used to call
// wireProxyAudit only after Restore had already returned, and after
// InstallTrustAnchor too — itself another live control-port round trip, with
// a read deadline a hostile guest controls the far end of
// (internal/sandbox/sandbox.go's InstallTrustAnchor). Every egress attempt,
// secret use, and withheld-credential decision made in that whole window went
// unrecorded: the proxy still enforced its allowlist, but
// OnEvent/OnSecret/OnWithheld/OnScrubbed were nil, so none of it reached the
// flight recorder. A guest that stalled the trust anchor reply, or refused it
// outright, could make snapshotRestore return before recorder.Open ever ran
// at all — zero audit events for the whole restore.
//
// Reproducing that timing for real needs an actual guest resuming across an
// actual Firecracker control port, which needs KVM this repository's test
// suite does not assume every machine has (see requireSandbox's convention in
// internal/sandbox/integration_test.go). TestWiringBeforeLiveWindowMatters,
// alongside this test, is the closest a machine without KVM can get: it
// proves the general mechanism — that an attempt made through a proxy is only
// ever recorded when wireProxyAudit ran before the attempt — with the real
// egress.Proxy, recorder.Recorder and wireProxyAudit this file uses, minus
// the VM.
//
// What this test adds on top, cheaply and on every commit with no VM
// involved at all: it reads snapshotRestore's own source and checks that the
// call to wireProxyAudit is textually before the call to sandbox.Restore.
// That ordering is what keeps the hooks live for the entire window above,
// and a future edit that puts wireProxyAudit back after Restore — the exact
// shape of the original bug — fails this test immediately, without needing
// Firecracker to prove it. Same technique as this package's
// TestEveryFileThatBuildsAProxyWiresItsAudit: read the source, do not trust
// a list.
func TestSnapshotRestoreWiresAuditBeforeResume(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "snapshot.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing snapshot.go: %v", err)
	}

	var fn *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		if f, ok := n.(*ast.FuncDecl); ok && f.Name.Name == "snapshotRestore" {
			fn = f
			return false
		}
		return true
	})
	if fn == nil {
		t.Fatal("snapshotRestore not found in snapshot.go — this test is looking in the wrong place")
	}

	var wirePos, restorePos token.Pos
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			if fun.Name == "wireProxyAudit" {
				wirePos = call.Pos()
			}
		case *ast.SelectorExpr:
			if id, ok := fun.X.(*ast.Ident); ok && id.Name == "sandbox" && fun.Sel.Name == "Restore" {
				restorePos = call.Pos()
			}
		}
		return true
	})

	if wirePos == token.NoPos {
		t.Fatal("snapshotRestore no longer calls wireProxyAudit — a restored sandbox would record " +
			"nothing about egress (no attempt, allowed or blocked, and no credential use)")
	}
	if restorePos == token.NoPos {
		t.Fatal("snapshotRestore no longer calls sandbox.Restore — this test is looking in the wrong place")
	}
	if wirePos > restorePos {
		t.Error("wireProxyAudit is called after sandbox.Restore in snapshotRestore; sandbox.Restore " +
			"resumes the guest and lets it round-trip over the control port before returning, so calling " +
			"wireProxyAudit afterward reopens the unaudited restore window this test guards against — wire " +
			"the audit hooks, with the sandbox id already known, before calling sandbox.Restore")
	}
}
