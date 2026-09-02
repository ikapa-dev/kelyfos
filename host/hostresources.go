package main

import (
	"runtime"
)

// The host's own ceilings (audit 2026-09-01, A8).
//
// A policy file is a ceiling a person wrote; the machine is a ceiling nobody
// can edit. serve-mcp's resolve enforces the first on every path and — since
// this audit — the second on every path too: a client launched from a
// directory with no kelyfos.toml above it used to name its own cpus and mem,
// and a request for 262144 MiB or 4096 vcpu went to Firecracker verbatim.
//
// The headroom is deliberate and stated: the host itself — the CLI, the VMM,
// the proxy, everything else running on it — needs memory that no sandbox
// accounts for, and a machine that hands its last gigabyte to a guest is a
// machine that OOM-kills unpredictably. A quarter of total RAM is kept, or
// 2 GiB where that is larger — but only as far as the 512 MiB guest floor
// below permits. Below roughly 2.5 GiB of total RAM the 2 GiB reservation
// would leave the guest under that floor, the floor wins, and less than 2 GiB
// ends up kept: "never less than 2 GiB kept" holds only on a host large enough
// to afford it, and is not a second guarantee alongside the floor.

// hostHeadroomMiB is the memory kept for the host itself, or the floor of
// what is kept when the machine is small.
const hostHeadroomMiB = 2048

// hostMinMachineMiB is the smallest machine this door will still boot, so a
// small host refuses gracefully instead of arithmetically. On a small host
// this floor overrides the 2 GiB headroom above (see the block comment).
const hostMinMachineMiB = 512

// hostCPUCeiling is the most vcpu a guest may be given: the cores this
// machine actually has. A guest seeing more cores than exist is a guest
// scheduling onto cores that do not.
//
// A var, not a func, so a test can pin the ceiling to a known value rather
// than to whatever the machine running it happens to have — the clamp/refuse
// split M1 turns on the exact number, and a test cannot assert against
// runtime.NumCPU().
var hostCPUCeiling = func() int {
	return runtime.NumCPU()
}

// hostMemCeilingMiB is the largest guest RAM this host can carry. A var for
// the same reason hostCPUCeiling is.
var hostMemCeilingMiB = func() int {
	total, ok := hostTotalMemMiB()
	if !ok {
		// Cannot read the machine's memory: do not pretend to know. The
		// policy ceiling and the config's own parse bounds still apply; this
		// is one layer that silently disappears rather than one that lies.
		return 0
	}
	headroom := total / 4
	if headroom < hostHeadroomMiB {
		headroom = hostHeadroomMiB
	}
	ceiling := total - headroom
	if ceiling < hostMinMachineMiB {
		ceiling = hostMinMachineMiB
	}
	return ceiling
}
