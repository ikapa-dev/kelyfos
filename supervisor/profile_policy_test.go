package main

import (
	"runtime"
	"testing"
)

// The audit of 2026-09-01's A5: the refusal policy is name-keyed against a
// hand-maintained per-architecture map, and a name absent from the map is
// silently dropped from the compiled filter — which is exactly how open_tree
// and fsopen came to reach the kernel. The failure was not that the map was
// wrong; it was that nothing failed when the map went stale.
//
// So this is the drift gate: every name the policy lists must resolve on the
// architecture this test compiles for, or the name is in archAbsent with a
// reason a reader can check. CI runs on both linux/arm64 and linux/amd64, so
// a policy name added without its number in either map fails there, in the
// commit that forgot it, instead of in a guest two releases later.
func TestEveryPolicyNameResolvesOnThisArchitecture(t *testing.T) {
	// Names the policy lists that genuinely do not exist on this arch, with
	// the reason. A name here must stay accurate: the map is the arbiter, so
	// if the arch gains the syscall, this entry masks a silent drop.
	absent := map[string]string{
		"settimeofday": "aarch64 has no settimeofday; clock_settime is the only clock setter",
	}
	if runtime.GOARCH == "amd64" {
		delete(absent, "settimeofday") // x86_64 has it, and the map maps it
	}

	for _, name := range refusalPolicy {
		nr, ok := syscallNumbers[name]
		if ok && nr >= 0 {
			continue
		}
		reason, known := absent[name]
		if !known {
			t.Errorf("policy name %q resolves to no syscall (%d) on %s and is not in this "+
				"test's known-absent list — add its number to profile_%s.go or document "+
				"the absence here with a reason", name, nr, runtime.GOARCH, runtime.GOARCH)
			continue
		}
		_ = reason // the entry documents why the absence is real
	}

	// The new mount-API names specifically: the audit's finding was these,
	// so their presence is asserted by name rather than as part of the mass.
	// fsconfig is here on its own evidence — the first probe run against the
	// corrected filter returned EINVAL, the kernel's answer, and only the
	// name missing from the policy explained it.
	for _, name := range []string{
		"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
		"process_vm_readv", "process_vm_writev", "pidfd_open", "pidfd_getfd", "pidfd_send_signal",
	} {
		if nr, ok := syscallNumbers[name]; !ok || nr < 0 {
			t.Errorf("%s does not resolve on %s (%d, %v); the fd-based mount API and the "+
				"cross-memory family must be refused on every architecture",
				name, runtime.GOARCH, nr, ok)
		}
	}
}
