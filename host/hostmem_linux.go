//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// hostTotalMemMiB reads the machine's physical memory from /proc/meminfo,
// where the guests actually run. ok is false when the file will not say.
//
// MemTotal is the machine's RAM, not a cgroup's memory.max: run serve-mcp
// itself inside a container capped below the host's memory and this still
// reads the host figure, so the ceiling is permissive by exactly that gap.
// The guests here run on the machine rather than in such a container, so the
// machine's total is the right number; a future host that ran serve-mcp under
// a memory-limited cgroup would want the cgroup's limit instead.
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
