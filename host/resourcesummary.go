package main

import "github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"

// blockedPackets reads a sandbox's egress drop counter for the resource.summary
// event that reports it, or zero for a sandbox with no network interface at
// all — the same "no interface, not merely no traffic" distinction the rest of
// that event already draws for its other fields.
//
// internal/sandbox/network.go's BlockedPackets had no caller anywhere before
// this (F14 (2)). Centralized here rather than inlined at each of the several
// call sites that build a resource.summary event, so a nil network reads as
// zero the same way in all of them instead of five near-identical checks
// drifting apart.
func blockedPackets(net *sandbox.Network) int64 {
	if net == nil {
		return 0
	}
	return net.BlockedPackets()
}
