package main

import "testing"

// F14 (2): internal/sandbox/network.go's BlockedPackets had no caller
// anywhere, and the fix wires it into every resource.summary event through
// this helper. The one thing worth pinning at this layer without a real
// sandbox is the nil case every un-networked sandbox hits: a sandbox with no
// network interface at all reads as zero blocked packets, not a crash and not
// a call into a nil *sandbox.Network.
func TestBlockedPacketsIsZeroWithNoNetwork(t *testing.T) {
	if got := blockedPackets(nil); got != 0 {
		t.Errorf("blockedPackets(nil) = %d, want 0", got)
	}
}
