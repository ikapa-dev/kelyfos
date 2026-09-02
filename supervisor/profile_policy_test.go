package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// The audit of 2026-09-01's A5/M8: the refusal policy is name-keyed against a
// hand-maintained per-architecture map, and a name absent from the map is
// silently dropped from the compiled filter — which is exactly how open_tree
// and fsopen came to reach the kernel. The failure was not that a map was
// wrong; it was that nothing failed when a map went stale.
//
// The old drift gate checked only the map the test was compiled against, and
// hosted CI's checks job runs linux/amd64 alone — so an arm64-only omission
// (a name dropped from profile_arm64.go but kept on amd64) passed CI green and
// shipped in a guest. This gate closes that: it parses profile_amd64.go *and*
// profile_arm64.go from disk, regardless of the arch it runs on, and asserts
// every policy name resolves in both. A name dropped from either map fails the
// commit that dropped it, on whichever arch CI happens to be.
func TestEveryPolicyNameResolvesOnEveryArchitecture(t *testing.T) {
	amd64 := parseSyscallMap(t, "profile_amd64.go")
	arm64 := parseSyscallMap(t, "profile_arm64.go")

	// A parse that silently found nothing would make every "is a key" check
	// below pass vacuously, so guard the maps are non-empty first.
	if len(amd64) == 0 || len(arm64) == 0 {
		t.Fatalf("parsed an empty syscallNumbers map (amd64 %d, arm64 %d) — the parser found no map to check",
			len(amd64), len(arm64))
	}

	// Policy names that genuinely do not exist on an arch, keyed by GOARCH,
	// each with the reason. aarch64 has no settimeofday — clock_settime is its
	// only clock setter — so the policy name is dropped from that filter, not
	// faked. A name here must stay accurate: if the arch gains the syscall,
	// this entry would mask a silent drop, so the absence is asserted below
	// rather than merely skipped.
	archAbsent := map[string]map[string]string{
		"arm64": {"settimeofday": "aarch64 has no settimeofday; clock_settime is the only clock setter"},
	}

	check := func(arch string, m map[string]string) {
		for _, name := range refusalPolicy {
			if reason, absent := archAbsent[arch][name]; absent {
				if _, present := m[name]; present {
					t.Errorf("%s: %q is documented arch-absent (%s) but profile_%s.go has it — "+
						"remove the archAbsent entry or the map key", arch, name, reason, arch)
				}
				continue
			}
			sel, ok := m[name]
			if !ok {
				t.Errorf("%s: policy name %q is not a key in profile_%s.go — a name absent from the map "+
					"is dropped from the compiled filter and the syscall reaches the kernel", arch, name, arch)
				continue
			}
			// Each value is unix.SYS_<UPPER(name)>: the number is resolved by
			// the compiler from the kernel's own constant, so the only way it
			// can be wrong is a copy-paste of the wrong SYS_ name onto a key.
			if want := "SYS_" + strings.ToUpper(name); sel != want {
				t.Errorf("%s: %q maps to unix.%s in profile_%s.go, expected unix.%s", arch, name, sel, arch, want)
			}
		}
	}
	check("amd64", amd64)
	check("arm64", arm64)

	// The twelve names the 2026-09-01 audit added, asserted by name in both
	// maps: the fd-based mount API and the cross-memory / fd-theft family were
	// exactly what reached the kernel because a name was missing, so their
	// presence is pinned directly rather than left to the mass loop above.
	for _, name := range []string{
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"process_vm_readv", "process_vm_writev", "pidfd_open", "pidfd_getfd", "pidfd_send_signal",
	} {
		for arch, m := range map[string]map[string]string{"amd64": amd64, "arm64": arm64} {
			if _, ok := m[name]; !ok {
				t.Errorf("%s: audit name %q is missing from profile_%s.go; the fd-based mount API and the "+
					"cross-memory family must be refused on every architecture", arch, name, arch)
			}
		}
	}

	// Tie the on-disk parse for the arch this test is compiled for back to the
	// map the compiler actually built: if the parse and the compiled map
	// disagree on the set of keys, the parse is not reading what runs, and
	// every assertion above would be checking a file the filter never used.
	onDisk := map[string]map[string]string{"amd64": amd64, "arm64": arm64}[runtime.GOARCH]
	if onDisk == nil {
		t.Fatalf("no parsed map for the running arch %q — add profile_%s.go to the parse set",
			runtime.GOARCH, runtime.GOARCH)
	}
	for name := range syscallNumbers {
		if _, ok := onDisk[name]; !ok {
			t.Errorf("compiled syscallNumbers has %q but profile_%s.go as parsed does not — the parse is stale",
				name, runtime.GOARCH)
		}
	}
	for name := range onDisk {
		if _, ok := syscallNumbers[name]; !ok {
			t.Errorf("profile_%s.go lists %q but the compiled syscallNumbers does not", runtime.GOARCH, name)
		}
	}
	// Every compiled value resolves to a real syscall number on this arch.
	for name, nr := range syscallNumbers {
		if nr < 0 {
			t.Errorf("compiled syscallNumbers[%q] is %d on %s — a policy name resolved to no syscall",
				name, nr, runtime.GOARCH)
		}
	}
}

// parseSyscallMap reads the syscallNumbers composite literal out of a
// profile_<arch>.go source file and returns name -> unix selector (e.g.
// "init_module" -> "SYS_INIT_MODULE"). It parses the file as text, so it works
// for the arch the test is *not* compiled for — which is the whole point, since
// CI compiles one arch and has to check both.
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
