package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// Every file that resumes a machine into a recorder it already has open must
// also wire that machine's guest-event handler.
//
// This is the guard for F3, a bug that had already shipped in five places.
// memberOptions wired OnGuestEvent for a team member built from
// sandbox.Restore; host/fork.go, host/snapshot.go, host/sessions.go and
// host/servemcpstate.go's restore and fork tools each built a bare
// sandbox.Options{} for sandbox.Restore with none — and sandbox.go's
// serveEvents drops a guest frame silently when the handler is nil, so a
// guest OOM kill or a plugin crash on any restored, forked or resumed session
// left no trace in the flight recorder.
//
// The rule is per file rather than per function, the same reason
// TestEveryFileThatBuildsAProxyWiresItsAudit's is: a door's sandbox.Options
// literal and the recorder it is wired against can legitimately live in
// different functions of the same file (servemcpstate.go's toolFork builds
// both inside one goroutine; team.go's forkAgent gets its OnGuestEvent from
// memberOptions, defined earlier in the same file). A file is the smallest
// unit that holds the whole arrangement.
//
// Same shape as TestEveryMachineWiredToATeamAlsoReportsWhatItsGuestSees and
// TestEveryFileThatBuildsAProxyWiresItsAudit: read the source, do not trust a
// list.
func TestEveryFileThatRestoresASandboxWiresItsGuestEvents(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("parsing the host package: %v", err)
	}

	restores := map[string]bool{}
	opensRecorder := map[string]bool{}
	wiresEvents := map[string]bool{}

	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "sandbox" {
							switch sel.Sel.Name {
							case "Restore":
								restores[name] = true
							}
						}
						if id, ok := sel.X.(*ast.Ident); ok && id.Name == "recorder" && sel.Sel.Name == "Open" {
							opensRecorder[name] = true
						}
					}
				}
				// Either spelling counts: a key in a sandbox.Options literal, or
				// a field assigned on one afterwards — fork.go and snapshot.go
				// both do the latter because the id, and so the recorder, has
				// to exist before the Options literal that names it.
				var field string
				switch v := n.(type) {
				case *ast.KeyValueExpr:
					if id, ok := v.Key.(*ast.Ident); ok {
						field = id.Name
					}
				case *ast.SelectorExpr:
					field = v.Sel.Name
				}
				if field == "OnGuestEvent" {
					wiresEvents[name] = true
				}
				return true
			})
		}
	}

	if len(restores) == 0 {
		t.Fatal("no sandbox.Restore call found in the host package — this test is looking in the wrong place")
	}

	checked := 0
	for file := range restores {
		// A file that never opens its own recorder (host/bench.go's timing
		// harness, which restores a throwaway machine per sample and keeps no
		// session at all) has nothing for a guest event to land in, and is not
		// one of the doors F3 is about.
		if !opensRecorder[file] {
			continue
		}
		checked++
		if !wiresEvents[file] {
			t.Errorf("%s restores a sandbox into a recorder it opens and never wires OnGuestEvent, "+
				"so an OOM kill or a plugin crash on that machine leaves no trace at all", file)
		}
	}
	if checked == 0 {
		t.Fatal("no file both opens a recorder and calls sandbox.Restore — this test is looking in the wrong place")
	}
}

// And the same thing said once at run time: guestEventRecorder, the closure
// every one of those files now builds its handler with, actually turns what
// the guest reports into what the chain holds — the OOM case with its RSS and
// cap, and the plugin-crash case with its reason — exactly as memberOptions's
// inline version already did before it was factored out.
func TestGuestEventRecorderWritesWhatTheGuestReported(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	rec, err := recorder.Open(sandbox.Root(), "session-under-test")
	if err != nil {
		t.Fatal(err)
	}

	handler := guestEventRecorder(rec, "worker-1", 512)
	handler(proto.GuestEvent{Type: proto.GuestEventOOM, PID: 57, Comm: "python3", RSSKiB: 230016})
	handler(proto.GuestEvent{Type: proto.GuestEventPluginCrash, Name: "linter", Message: "exited"})

	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(recorder.Path(sandbox.Root(), "session-under-test"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		t.Fatal(err)
	}

	var sawOOM, sawCrash bool
	for _, e := range events {
		switch e.Type {
		case recorder.TypeResourceOOM:
			sawOOM = true
			if e.Source != recorder.SourceGuest || e.Agent != "worker-1" || e.PID != 57 ||
				e.Comm != "python3" || e.RSSKiB != 230016 || e.MemMiB != 512 {
				t.Errorf("resource.oom event = %+v, missing what the guest and the caller supplied", e)
			}
		case recorder.TypePluginCrash:
			sawCrash = true
			if e.Source != recorder.SourceGuest || e.Agent != "worker-1" || e.Name != "linter" ||
				e.Reason != "exited" {
				t.Errorf("plugin.crash event = %+v, missing what the guest and the caller supplied", e)
			}
		}
	}
	if !sawOOM {
		t.Error("no resource.oom event was recorded for a GuestEventOOM the handler was given")
	}
	if !sawCrash {
		t.Error("no plugin.crash event was recorded for a GuestEventPluginCrash the handler was given")
	}
}
