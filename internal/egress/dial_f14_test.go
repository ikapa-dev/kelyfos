package egress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"
)

// f14Reserved is every range an allowlisted public name has no business
// resolving to, with the reason it is here. The Control hook is asked about
// each one directly: it is handed the numeric address the kernel is about to
// connect to, which is exactly what a resolver would have produced, so this
// exercises the real refusal path without needing a resolver that lies.
var f14Reserved = []struct{ addr, why string }{
	{"0.0.0.0", "the unspecified address"},
	{"0.1.2.3", `RFC 1122 "this network" — the whole /8, not only 0.0.0.0`},
	{"10.0.0.5", "RFC 1918 private"},
	{"100.64.0.1", "RFC 6598 CGNAT, low end"},
	{"100.100.100.200", "Alibaba Cloud instance metadata, inside CGNAT space"},
	{"100.127.255.254", "RFC 6598 CGNAT, high end"},
	{"100.101.5.5", "an ordinary Tailscale or WireGuard mesh peer"},
	{"127.0.0.1", "loopback"},
	{"127.0.0.53", "the systemd-resolved stub, still loopback"},
	{"169.254.169.254", "AWS, GCP and Azure instance metadata"},
	{"169.254.1.1", "link-local generally"},
	{"168.63.129.16", "the Azure wireserver — public space, caught by no range rule"},
	{"172.16.0.5", "RFC 1918 private"},
	{"192.0.0.1", "RFC 6890 IETF protocol assignments"},
	{"192.0.0.170", "NAT64/DNS64 discovery, inside that /24"},
	{"192.168.1.1", "RFC 1918 private"},
	{"192.0.2.5", "TEST-NET-1, a documentation range"},
	{"198.18.0.1", "RFC 2544 benchmarking, often locally routed to real devices"},
	{"198.51.100.5", "TEST-NET-2"},
	{"203.0.113.5", "TEST-NET-3"},
	{"224.0.0.1", "multicast"},
	{"240.0.0.1", "RFC 1112 reserved"},
	{"255.255.255.255", "limited broadcast"},
	{"::", "the unspecified address"},
	{"::1", "loopback"},
	{"fe80::1", "link-local"},
	{"fc00::1", "unique local, low end"},
	{"fdff::1", "unique local, high end"},
	{"ff02::1", "link-local all-nodes multicast"},
	{"ff01::1", "interface-local multicast"},
	{"::ffff:10.0.0.1", "an IPv4-mapped private address"},
	{"::ffff:169.254.169.254", "instance metadata, IPv4-mapped"},
	{"64:ff9b::a00:1", "NAT64 carrying 10.0.0.1"},
	{"64:ff9b::a9fe:a9fe", "NAT64 carrying 169.254.169.254 — the metadata address, in v6 clothing"},
	{"64:ff9b:1::1", "RFC 8215 local-use NAT64, never global"},
	{"2002:a00:1::1", "6to4 carrying 10.0.0.1: the host tunnels it to that v4 address"},
	{"2002:a9fe:a9fe::1", "6to4 carrying 169.254.169.254"},
	{"::a00:1", "the deprecated IPv4-compatible form of 10.0.0.1"},
}

// f14Public is what must still be dialled. A range check that refuses these
// has broken egress rather than secured it.
var f14Public = []string{
	"93.184.216.34", "1.1.1.1", "8.8.8.8", "140.82.121.4",
	"99.255.255.255", "100.63.255.255", "100.128.0.0",
	"168.63.129.15", "168.63.129.17",
	"192.0.1.255", "192.0.3.0", "198.17.255.255", "198.20.0.0",
	"2606:4700:4700::1111", "2a00:1450:4001:81b::200e",
	"64:ff9b::8080:808", "2002:5db8:d822::1", "2001:4860:4860::8888",
}

// The finding: the resolved-address check runs on every dial, and its range
// list is short. Asked through the Control hook the dialers actually install,
// so this is the refusal as it happens rather than a predicate in isolation.
func TestF14_TheControlHookRefusesEveryReservedRange(t *testing.T) {
	hook := refuseUnsafeResolvedAddr("api.example.com")
	for _, c := range f14Reserved {
		if err := hook("tcp", net.JoinHostPort(c.addr, "443"), nil); err == nil {
			t.Errorf("%s (%s) was dialled — an allowlisted name resolving there must be refused",
				c.addr, c.why)
		}
	}
	for _, addr := range f14Public {
		if err := hook("tcp", net.JoinHostPort(addr, "443"), nil); err != nil {
			t.Errorf("%s is routable public space and must still be dialled: %v", addr, err)
		}
	}
}

// The 403 is written into the guest. Naming the address the proxy declined to
// dial hands a compromised agent the result of a DNS lookup it may not be able
// to perform itself — free reconnaissance about the host's network, one
// allowlisted name at a time. The reason and the fix are the guest's business;
// the address is the operator's, and it belongs in the recorder.
func TestF14_TheRefusalDoesNotEchoTheResolvedAddressToTheGuest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should never be reached")
	}))
	defer upstream.Close()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	attempts := make(chan Attempt, 4)
	p := &Proxy{Policy: Policy{Allow: []string{"localhost"}, Ports: []int{atoiOrZero(portStr)}}}
	p.OnEvent = func(a Attempt) { attempts <- a }
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	target := "localhost:" + portStr
	fmt.Fprintf(raw, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if strings.Contains(string(body), "127.0.0.1") {
		t.Errorf("the refusal names the resolved address to the guest, which is reconnaissance "+
			"it does not need:\n%s", body)
	}
	if !strings.Contains(string(body), "an address this proxy will not dial") {
		t.Errorf("the refusal does not say what happened:\n%s", body)
	}
}

// lastAddrIn is the last address a prefix contains.
func lastAddrIn(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	bits := p.Bits()
	for i := bits; i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Every prefix is refused at both its edges, and the addresses immediately
// outside it are not — unless they belong to another entry, which is how
// 224.0.0.0/4 and 240.0.0.0/4 meet.
//
// The boundaries are computed from the table rather than written out beside
// it. A hand-written "just outside" address is a second copy of the prefix
// arithmetic, and the day somebody widens a prefix and forgets to move its
// neighbour, the test agrees with itself and not with the code.
func TestF14_EveryUnsafePrefixHasExactBoundaries(t *testing.T) {
	covered := func(a netip.Addr, except netip.Prefix) bool {
		for _, p := range unsafePrefixes {
			if p == except {
				continue
			}
			if p.Contains(a) {
				return true
			}
		}
		if _, ok := embeddedV4(a); ok {
			return true // an embedding range; what it carries decides, not the prefix
		}
		return false
	}

	for _, p := range unsafePrefixes {
		first, last := p.Masked().Addr(), lastAddrIn(p)
		for _, in := range []netip.Addr{first, last} {
			if !isUnsafeResolvedAddr(in) {
				t.Errorf("%s is inside %s and was not refused", in, p)
			}
		}
		for _, out := range []netip.Addr{first.Prev(), last.Next()} {
			if !out.IsValid() || covered(out, p) {
				continue // the address space ends here, or a neighbouring entry owns it
			}
			if isUnsafeResolvedAddr(out) {
				t.Errorf("%s is immediately outside %s and was refused anyway — the prefix "+
					"reaches further than it says it does", out, p)
			}
		}
	}
}

// The table, stated independently of the table.
//
// TestF14_EveryUnsafePrefixHasExactBoundaries computes each prefix's edges FROM
// that prefix, so it is circular with respect to width: narrowing an entry
// moves the edges it checks along with it and the test still passes. It catches
// neighbour drift, which is what it was written for, and nothing about how wide
// a range is. The differential sweep covers the ranges the old predicates
// refused — but 198.18.0.0/15 and the documentation ranges are F14's own
// additions, so no frozen predicate speaks for them, and narrowing either
// passed everything.
//
// This is the second statement of the same fact, which is the only thing that
// catches a one-character change to the first. Adding, removing or resizing a
// range means editing this list on purpose.
func TestF14_TheTableIsExactlyThis(t *testing.T) {
	want := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"168.63.129.16/32",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"64:ff9b:1::/48",
		"::/128",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	}
	var got []string
	for _, p := range unsafePrefixes {
		got = append(got, p.String())
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the refused-prefix table has changed.\n got: %s\nwant: %s\n"+
			"If that was deliberate, say so here too — this list exists so a prefix cannot be "+
			"narrowed, widened or dropped by a one-character edit that every other test agrees with.",
			strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}

	// The three that are checked by what they carry rather than by what they
	// are, pinned for the same reason.
	for _, c := range []struct {
		got  netip.Prefix
		want string
	}{
		{nat64WellKnown, "64:ff9b::/96"},
		{sixToFour, "2002::/16"},
		{v4Compatible, "::/96"},
	} {
		if c.got.String() != c.want {
			t.Errorf("embedded-v4 prefix = %s, want %s", c.got, c.want)
		}
	}
}

// legacyUnsafeResolvedIP is the predicate stack this replaced, frozen.
//
// Kept because the danger in swapping seven standard-library predicates for a
// hand-written table is not the ranges somebody remembered to add — those are
// the visible half — but the ones the predicates covered silently and nobody
// thought to re-add. This is the differential: whatever the old code refused,
// the new code must still refuse.
func legacyUnsafeResolvedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate()
}

// The differential, as arithmetic rather than as sampling.
//
// The first version of this swept 2058 addresses and varied only the FIRST
// octet, with five fixed patterns for the rest — so narrowing 172.16.0.0/12 to
// /13 or 192.168.0.0/16 to /17 passed it, and those are the two RFC 1918
// ranges this test exists to protect. Sampling a prefix cannot show that the
// prefix got narrower; only walking the boundary can.
//
// So this walks every /16 in the v4 space at both edges of its third and
// fourth octets — 65,536 blocks, four addresses each — which straddles any
// narrowing at /16 or coarser, and adds the exact edges of every legacy range
// as named cases for narrowing finer than that.
func TestF14_NoRangeTheOldPredicatesCaughtIsLost(t *testing.T) {
	var checked int
	consider := func(a netip.Addr) {
		checked++
		if legacyUnsafeResolvedIP(net.IP(a.AsSlice())) && !isUnsafeResolvedAddr(a) {
			t.Fatalf("%s was refused by the predicates this table replaced and is now dialled", a)
		}
	}

	for hi := 0; hi < 256; hi++ {
		for lo := 0; lo < 256; lo++ {
			// Both ends of the /16, so a table entry that lost its lower half
			// or its upper half is caught either way.
			consider(netip.AddrFrom4([4]byte{byte(hi), byte(lo), 0, 1}))
			consider(netip.AddrFrom4([4]byte{byte(hi), byte(lo), 255, 254}))
		}
	}
	// The edges of every range the predicates name, to the address. A /12 or a
	// /24 narrowed by one bit moves a boundary the /16 walk above steps over.
	for _, s := range []string{
		"10.0.0.0", "10.255.255.255",
		"127.0.0.0", "127.255.255.255",
		"169.254.0.0", "169.254.255.255",
		"172.16.0.0", "172.31.255.255", "172.24.0.1", "172.20.13.7",
		"192.168.0.0", "192.168.255.255", "192.168.128.1", "192.168.200.50",
		"224.0.0.0", "239.255.255.255",
		"0.0.0.0",
	} {
		consider(netip.MustParseAddr(s))
	}
	// The same v4 space in its IPv4-mapped v6 spelling, which Go's predicates
	// handle by calling To4() first and which the table only sees because
	// isUnsafeResolvedAddr unmaps.
	for hi := 0; hi < 256; hi++ {
		for lo := 0; lo < 256; lo += 8 {
			a := netip.AddrFrom4([4]byte{byte(hi), byte(lo), 1, 1})
			consider(netip.AddrFrom16(a.As16()))
		}
	}
	// IPv6: every /8, both ends of the second byte, plus the addresses the
	// predicates name outright.
	for hi := 0; hi < 256; hi++ {
		for _, second := range []byte{0x00, 0xff} {
			var b [16]byte
			b[0], b[1], b[15] = byte(hi), second, 1
			consider(netip.AddrFrom16(b))
		}
	}
	for _, s := range []string{"::", "::1", "fe80::1", "febf::1", "fc00::1", "fdff::1",
		"ff01::1", "ff02::1", "ff0e::1", "2606:4700:4700::1111"} {
		consider(netip.MustParseAddr(s))
	}
	if checked < 131072 {
		t.Fatalf("only %d addresses were compared; this is meant to straddle every /16", checked)
	}
	t.Logf("%d addresses compared against the frozen predicate stack", checked)
}

// A link-local address that arrives with a zone — which is the shape a
// link-local resolution actually takes — must still be refused.
// netip.Prefix.Contains returns false for any address carrying a zone, so a
// table walked without stripping it fails open on precisely the range the
// check was written for.
func TestF14_AZonedLinkLocalAddressIsStillRefused(t *testing.T) {
	for _, s := range []string{"fe80::1%eth0", "fe80::1%1", "ff02::1%eth0"} {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test bug: %q: %v", s, err)
		}
		if !isUnsafeResolvedAddr(a) {
			t.Errorf("%s carries a zone and was dialled; Prefix.Contains is false for zoned "+
				"addresses, so the zone has to be dropped before the table is walked", s)
		}
	}
}

// The address must reach the recorder, since the guest is no longer told it.
// Moving it out of the 403 without putting it anywhere would not be a fix, it
// would be the loss of the only fact that makes the refusal diagnosable.
func TestF14_TheResolvedAddressReachesTheRecorder(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	attempts := make(chan Attempt, 4)
	p := &Proxy{Policy: Policy{Allow: []string{"localhost"}, Ports: []int{atoiOrZero(portStr)}}}
	p.OnEvent = func(a Attempt) { attempts <- a }
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	target := "localhost:" + portStr
	fmt.Fprintf(raw, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := http.ReadResponse(bufio.NewReader(raw), nil); err != nil {
		t.Fatal(err)
	}

	select {
	case a := <-attempts:
		if a.Reason != ReasonUnsafeResolvedAddr {
			t.Fatalf("reason = %q, want %q", a.Reason, ReasonUnsafeResolvedAddr)
		}
		if a.ResolvedAddr == "" {
			t.Fatal("the refusal recorded no resolved address, so nothing anywhere now says " +
				"where the name actually pointed")
		}
		if a.ResolvedAddr != "127.0.0.1" {
			t.Errorf("resolved_addr = %q, want 127.0.0.1", a.ResolvedAddr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no egress.attempt was recorded")
	}
}

// The address that reaches the record is a bare address literal.
//
// netip.ParseAddr accepts an arbitrary zone and String() gives it back
// verbatim, so without normalising, whatever a resolver returned would land in
// the chain as the attempt's resolved_addr. Nothing guest-controlled reaches
// this today — a resolver supplies it, and allowsHost has already matched the
// name against the operator's own list — so this is a latent shape rather than
// a live one, and it is cheaper to close than to keep arguing about.
func TestF14_TheRecordedAddressIsNormalised(t *testing.T) {
	hook := refuseUnsafeResolvedAddr("api.example.com")
	for _, c := range []struct{ in, want string }{
		{"fe80::1%eth0", "fe80::1"},
		{"fe80::1%<script>alert(1)</script>", "fe80::1"},
		{"::ffff:169.254.169.254", "169.254.169.254"},
		{"169.254.169.254", "169.254.169.254"},
	} {
		err := hook("tcp", net.JoinHostPort(c.in, "443"), nil)
		if err == nil {
			t.Errorf("%s was dialled", c.in)
			continue
		}
		var unsafe *errUnsafeResolvedAddr
		if !errors.As(err, &unsafe) {
			t.Errorf("%s: refused for the wrong reason: %v", c.in, err)
			continue
		}
		if unsafe.addr != c.want {
			t.Errorf("the record would carry %q for %q, want %q", unsafe.addr, c.in, c.want)
		}
	}
}
