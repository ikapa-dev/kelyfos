//go:build linux

package sandbox

import "syscall"

// vmmSpawnAttr is the SysProcAttr every VMM spawn uses, split by build tag
// because PDEATHSIG is a Linux-only field: the darwin CLI never boots a
// machine, but it must still COMPILE (the release workflow builds
// kelyfos-darwin-* from this same tree — the second review's finding 1, a
// build break CI on Linux cannot see).
//
// The SIGKILL PDEATHSIG takes the VMM's direct child down with this process:
// the unjailed VMM outright, the jailed one's sudo wrapper — the watchdog
// (watchdog.go) covers the rest of that chain. The signal fires on the death
// of the forking THREAD, not the process, so nothing on the host may call
// LockOSThread across a spawn (supervisor/confine.go and dev/seccomp-probe
// are the only callers that do, and neither spawns a VMM).
func vmmSpawnAttr(sig syscall.Signal) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: sig}
}

// watchdogSpawnAttr is the watchdog's own spawn attribute: SIGTERM, not
// SIGKILL, because the watchdog's dying act IS the cleanup.
func watchdogSpawnAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}
