package sandbox

import (
	"net"
	"testing"
)

// The derivation walks the whole link-local /16 as /30s, and one of those /30s
// holds 169.254.169.254. No sandbox may be handed it.
//
// The whole index space is enumerated rather than sampled because the bad index
// is a single one out of 16,384: a seeded or sampled test finds it about as
// often as production does, which is to say once every few thousand runs, long
// after anyone is still watching.
func TestNoDerivedSandboxRangeCoversTheCloudMetadataAddress(t *testing.T) {
	metadata := net.IPv4(169, 254, 169, 254)
	for idx := 0; idx < 16384; idx++ {
		hostIP, guestIP, ok := deriveAddrs(uint16(idx))
		if !ok {
			continue
		}
		for _, ip := range []net.IP{hostIP, guestIP} {
			if ip.Equal(metadata) {
				t.Fatalf("index %d hands a sandbox %s, the cloud metadata address (host %s, guest %s)",
					idx, ip, hostIP, guestIP)
			}
		}
		// The address itself is the second usable in its /30, so it is always
		// the guest half — but the whole block is claimed by the connected
		// route `ip addr add <host>/30` installs, so overlap is the real test.
		if sameSlash30(hostIP, metadata) {
			t.Fatalf("index %d puts a sandbox on %s/30, which contains %s", idx, hostIP, metadata)
		}
	}
}

// The skip has to cost exactly one index. Rejecting more would silently shrink
// the pool the collision retry draws from, and rejecting none is the defect.
func TestExactlyOneDerivedRangeIsReserved(t *testing.T) {
	var rejected []int
	for idx := 0; idx < 16384; idx++ {
		if _, _, ok := deriveAddrs(uint16(idx)); !ok {
			rejected = append(rejected, idx)
		}
	}
	if len(rejected) != 1 || rejected[0] != 10879 {
		t.Fatalf("reserved indices = %v, want exactly [10879] (169.254.169.252/30)", rejected)
	}
}

// A restored guest dials the proxy at an address baked into its memory (D22),
// so the addressing every other index produces must not move. Host is the first
// usable address of its /30 and guest the second, as it has always been.
func TestDerivedAddressingIsUnchangedForEveryOtherIndex(t *testing.T) {
	for idx := 0; idx < 16384; idx++ {
		hostIP, guestIP, ok := deriveAddrs(uint16(idx))
		if !ok {
			continue
		}
		wantHost := net.IPv4(169, 254, byte(idx>>6), byte((idx&63)*4+1))
		wantGuest := net.IPv4(169, 254, byte(idx>>6), byte((idx&63)*4+2))
		if !hostIP.Equal(wantHost) || !guestIP.Equal(wantGuest) {
			t.Fatalf("index %d derived %s/%s, want %s/%s", idx, hostIP, guestIP, wantHost, wantGuest)
		}
	}
}
