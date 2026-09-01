//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// hostTotalMemMiB reads the machine's physical memory from /proc/meminfo,
// where the guests actually run. ok is false when the file will not say.
func hostTotalMemMiB() (int, bool) {
	blob, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(blob), "\n") {
		// "MemTotal:       16384000 kB"
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0, false
		}
		return kb / 1024, true
	}
	return 0, false
}
