package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// The audit of 2026-09-01's A5/M8: the refusal policy is name-keyed against a
// hand-maintained map, and a name absent from the map is a syscall reaching
// the kernel — which is exactly how open_tree and fsopen came to reach it. The
// failure was not that a map was wrong; it was that nothing failed when a map
// went stale.
//
// Since D102 there is one map for every architecture (profile_syscalls.go), so
// an omission cannot be architecture-specific any more: the compiler refuses a
// selector the running architecture lacks, and this gate refuses a name the
// map lacks. It parses the file from disk, because the property "the value for
// `mount` is unix.SYS_MOUNT and not a neighbour's constant" is one the compiled
// map cannot state about itself.
func TestEveryPolicyNameResolves(t *testing.T) {
	onDisk := parseSyscallMap(t, "profile_syscalls.go")

	// A parse that silently found nothing would make every "is a key" check
	// below pass vacuously, so guard the map is non-empty first.
	if len(onDisk) == 0 {
		t.Fatal("parsed an empty syscallNumbers map — the parser found no map to check")
	}

	for _, name := range refusalPolicy {
		sel, ok := onDisk[name]
		if !ok {
			t.Errorf("policy name %q is not a key in profile_syscalls.go — a name absent from the map "+
				"is a filter deniedSyscalls refuses to build", name)
			continue
		}
		// Each value is unix.SYS_<UPPER(name)>: the number is resolved by the
		// compiler from the kernel's own constant, so the only way it can be
		// wrong is a copy-paste of the wrong SYS_ name onto a key.
		if want := "SYS_" + strings.ToUpper(name); sel != want {
			t.Errorf("%q maps to unix.%s in profile_syscalls.go, expected unix.%s", name, sel, want)
		}
	}

	// The twelve names the 2026-09-01 audit added, asserted by name: the
	// fd-based mount API and the cross-memory / fd-theft family were exactly
	// what reached the kernel because a name was missing, so their presence is
	// pinned directly rather than left to the loop above.
	for _, name := range []string{
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"process_vm_readv", "process_vm_writev", "pidfd_open", "pidfd_getfd", "pidfd_send_signal",
	} {
		if _, ok := onDisk[name]; !ok {
			t.Errorf("audit name %q is missing from profile_syscalls.go; the fd-based mount API and the "+
				"cross-memory family must be refused on every architecture", name)
		}
	}
	// settimeofday, asserted by name because it is the one the aarch64 map
	// used to omit on a false belief about the architecture (D102).
	if _, ok := onDisk["settimeofday"]; !ok {
		t.Error("settimeofday is missing from profile_syscalls.go")
	}

	// Tie the on-disk parse back to the map the compiler actually built: if
	// the two disagree on the set of keys, the parse is not reading what runs,
	// and every assertion above would be checking a file the filter never used.
	for name := range syscallNumbers {
		if _, ok := onDisk[name]; !ok {
			t.Errorf("compiled syscallNumbers has %q but profile_syscalls.go as parsed does not — the parse is stale", name)
		}
	}
	for name := range onDisk {
		if _, ok := syscallNumbers[name]; !ok {
			t.Errorf("profile_syscalls.go lists %q but the compiled syscallNumbers does not", name)
		}
	}
	// Every compiled value resolves to a real syscall number on this arch.
	for name, nr := range syscallNumbers {
		if nr < 0 {
			t.Errorf("compiled syscallNumbers[%q] is %d — a policy name resolved to no syscall", name, nr)
		}
	}
	// And the filter the policy compiles to refuses every name, none dropped.
	if got, want := len(profileFor("base").Refused()), len(refusalPolicy); got != want {
		t.Errorf("the base profile refuses %d syscalls, the policy names %d", got, want)
	}
}

// parseSyscallMap reads the syscallNumbers composite literal out of a source
// file and returns name -> unix selector (e.g. "init_module" ->
// "SYS_INIT_MODULE"), so the test can state which constant a name was given.
func parseSyscallMap(t *testing.T, path string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != "syscallNumbers" || i >= len(vs.Values) {
					continue
				}
				cl, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					t.Fatalf("%s: syscallNumbers is not a composite literal", path)
				}
				for _, e := range cl.Elts {
					kv, ok := e.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.BasicLit)
					if !ok || key.Kind != token.STRING {
						continue
					}
					syscallName, err := strconv.Unquote(key.Value)
					if err != nil {
						t.Fatalf("%s: bad key %q: %v", path, key.Value, err)
					}
					sel, ok := kv.Value.(*ast.SelectorExpr)
					if !ok {
						t.Errorf("%s: value for %q is not a unix.SYS_* selector", path, syscallName)
						continue
					}
					if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "unix" {
						t.Errorf("%s: value for %q is not qualified by unix", path, syscallName)
						continue
					}
					out[syscallName] = sel.Sel.Name
				}
			}
		}
	}
	return out
}
