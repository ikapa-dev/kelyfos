//go:build !linux

package sandbox

import "syscall"

// vmmSpawnAttr on a host that cannot boot a machine: the own-process-group
// bit is all that applies, and PDEATHSIG does not exist (the second review's
// finding 1 — the darwin release build broke on this field).
func vmmSpawnAttr(syscall.Signal) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func watchdogSpawnAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
