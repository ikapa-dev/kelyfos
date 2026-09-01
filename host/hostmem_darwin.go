//go:build darwin

package main

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// hostTotalMemMiB reads the machine's physical memory via sysctl, so the
// release CLI still builds and still knows its host on darwin. ok is false
// when the sysctl will not say, and the ceiling layer then stays out of the
// way rather than guessing.
func hostTotalMemMiB() (int, bool) {
	if runtime.GOOS == "darwin" {
		if v, err := unix.SysctlUint64("hw.memsize"); err == nil {
			return int(v / (1024 * 1024)), true
		}
	}
	return 0, false
}
