//go:build darwin

package main

import "golang.org/x/sys/unix"

// hostTotalMemMiB reads the machine's physical memory via sysctl, so the
// release CLI still builds and still knows its host on darwin. ok is false
// when the sysctl will not say, and the ceiling layer then stays out of the
// way rather than guessing.
//
// No runtime.GOOS check: the //go:build darwin tag already means this file is
// compiled only on darwin, so a check for it inside was dead.
func hostTotalMemMiB() (int, bool) {
	if v, err := unix.SysctlUint64("hw.memsize"); err == nil {
		return int(v / (1024 * 1024)), true
	}
	return 0, false
}
