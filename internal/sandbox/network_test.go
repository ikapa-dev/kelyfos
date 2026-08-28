package sandbox

import (
	"net"
	"strings"
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

// The ruleset half of F9, read rather than run: the line that makes HostIP
// private has to be in the input chain, and it has to be above the jump.
//
// Order is the assertion, not a stylistic preference. nftables evaluates a
// chain top to bottom and the jump is unconditional for anything arriving on
// the TAP; putting the drop after it would still work for a local process,
// because that packet never matches the jump — but the rule is written to be
// read as "nothing but the TAP reaches this address", and a reader who finds it
// underneath cannot tell whether it is doing anything at all.
func TestF9_RulesetDropsHostIPFromEverythingButTheTAP(t *testing.T) {
	n := &Network{
		TAP:       "kelyfos0123abcd",
		HostIP:    net.IPv4(169, 254, 8, 1),
		GuestIP:   net.IPv4(169, 254, 8, 2),
		Netmask:   "255.255.255.252",
		ProxyPort: 41234,
		table:     "kelyfos_0123abcd",
	}
	rs := n.ruleset()

	want := `ip daddr 169.254.8.1 iifname != "kelyfos0123abcd" counter drop`
	drop := strings.Index(rs, want)
	if drop < 0 {
		t.Fatalf("the input chain does not carry\n\t%s\ngot:\n%s", want, rs)
	}
	jump := strings.Index(rs, `iifname "kelyfos0123abcd" jump kelyfos_guest_in`)
	if jump < 0 {
		t.Fatalf("the jump into kelyfos_guest_in is gone:\n%s", rs)
	}
	if drop > jump {
		t.Errorf("the drop is below the jump; it belongs above it:\n%s", rs)
	}
	// The base chains stay `policy accept`: a drop policy on the input hook
	// filters every packet reaching the host, not only this sandbox's.
	if !strings.Contains(rs, "type filter hook input priority filter; policy accept;") {
		t.Errorf("the input base chain no longer has policy accept:\n%s", rs)
	}
}
