package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
)

// allowsHost and secretsFor decide purely on the hostname string a guest's
// CONNECT or request line named. Nothing about that string says where DNS
// will actually send the connection: an allowlisted domain that is
// DNS-hijacked, or simply taken over, can resolve to 169.254.169.254 — a
// cloud instance's metadata endpoint, on port 80, already in the proxy's
// always-allowed port set — and an ordinary CONNECT to that already-allowed
// name would be tunnelled straight there with nothing in tunnel, terminate's
// upstream leg or forwardHTTP ever having looked at the address the name
// actually resolved to (F2).
//
// The fix runs at the one point common to every dial: net.Dialer.Control,
// which fires once per address a resolver hands back, after resolution and
// immediately before the connect syscall for that address — so a domain with
// several A/AAAA records is checked on each attempt Go's own Happy-Eyeballs
// fallback makes, not merely its first.
//
// A host that is already a literal IP address never goes through a resolver
// at all — as every httptest.Server this package's own tests dial through
// is, and as an operator's policy entry naming a raw address literally is —
// so there is nothing here for DNS to have hijacked; the Control hook is
// wired in only when the host being dialled is a name.

// errUnsafeResolvedAddr is what refuseUnsafeResolvedAddr returns when a
// name's resolved address falls in unsafePrefixes: not somewhere a legitimate
// public allowlisted domain has any business resolving to. Carries the
// address for the flight recorder — and only for it. What goes back to the
// guest names no address at all (F14).
type errUnsafeResolvedAddr struct {
	host, addr string
}

func (e *errUnsafeResolvedAddr) Error() string {
	return fmt.Sprintf("%s resolved to %s, which this proxy refuses to dial", e.host, e.addr)
}

// unsafePrefixes is every range an allowlisted public name has no business
// resolving to, one entry per range with the reason it is here.
//
// A table rather than a stack of net.IP predicates, which is what this was:
// IsLoopback || IsLinkLocalUnicast || IsLinkLocalMulticast ||
// IsInterfaceLocalMulticast || IsMulticast || IsUnspecified || IsPrivate.
// Every one of those is correct and together they still missed CGNAT, most of
// 0.0.0.0/8, the IETF protocol block, benchmarking space, the whole reserved
// 240/4, and every v6 form that carries a v4 address inside it. The trouble is
// not that the predicates were wrong but that nobody can review them: the set
// they cover is spread across seven method bodies in the standard library, and
// what is missing from a set you cannot see is invisible too. A list of
// prefixes with a comment each can be read against RFC 6890 in a minute (F14).
//
// TestF14_NoRangeTheOldPredicatesCaughtIsLost holds the other half of that
// change: it keeps a frozen copy of the seven predicates and asserts this table
// still refuses everything they refused.
var unsafePrefixes = []netip.Prefix{
	// IPv4.
	netip.MustParsePrefix("0.0.0.0/8"),       // RFC 1122 "this network": all of it, not only 0.0.0.0
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC 1918 private
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 CGNAT: Alibaba Cloud IMDS is 100.100.100.200, and every Tailscale or WireGuard mesh peer is 100.x
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback, including the 127.0.0.53 resolver stub
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local: AWS, GCP and Azure instance metadata at 169.254.169.254
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC 1918 private
	netip.MustParsePrefix("192.0.0.0/24"),    // RFC 6890 IETF protocol assignments, including 192.0.0.170 NAT64 discovery
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1, documentation
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC 1918 private
	netip.MustParsePrefix("198.18.0.0/15"),   // RFC 2544 benchmarking, and often locally routed to real devices
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2, documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3, documentation
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast, link-local and interface-local included
	netip.MustParsePrefix("240.0.0.0/4"),     // RFC 1112 reserved, and 255.255.255.255 with it

	// One address, not a range, and the reason it needs its own line: the
	// Azure wireserver sits in ordinary public space. It is the instance
	// metadata endpoint on every Azure VM — the same asset 169.254.169.254 is
	// elsewhere — and no range rule will ever catch it. Kept separate above
	// the v6 block so it cannot be mistaken for one of the RFC ranges.
	netip.MustParsePrefix("168.63.129.16/32"), // Azure wireserver: public space, reachable, and not a reserved range

	// IPv6.
	// These two are reached by the ::/96 diversion below before this loop ever
	// runs — :: and ::1 are both inside it, and their embedded v4 forms 0.0.0.0
	// and 0.0.0.1 are refused by 0.0.0.0/8. Kept anyway, and annotated rather
	// than deleted: a table whose selling point is that it can be read against
	// RFC 6890 should say that the unspecified address and loopback are refused,
	// and if the ::/96 diversion is ever removed these stop being redundant the
	// same minute.
	netip.MustParsePrefix("::/128"),         // unspecified (already via ::/96)
	netip.MustParsePrefix("::1/128"),        // loopback (already via ::/96)
	netip.MustParsePrefix("64:ff9b:1::/48"), // RFC 8215 local-use NAT64: defined as never global
	netip.MustParsePrefix("fc00::/7"),       // unique local
	netip.MustParsePrefix("fe80::/10"),      // link-local
	netip.MustParsePrefix("ff00::/8"),       // multicast, all scopes
}

// The v6 ranges that carry a v4 address inside them. These are NOT blanket
// refusals: 64:ff9b::8.8.8.8 and 2002:5db8:d822::1 are legitimate ways to
// reach 8.8.8.8 and 93.184.216.34, and refusing the whole prefix would break
// them. What matters is the address inside, so it is extracted and checked by
// the same table — which is how 64:ff9b::a9fe:a9fe, the cloud metadata address
// wearing a v6 costume, is refused (F14).
var (
	// RFC 6052's well-known prefix. Only /96 is well-known, so the v4 is
	// always the last four bytes.
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	// RFC 3056 6to4. The host tunnels these as IPv4 to the embedded address,
	// so 2002:a00:1::1 really does put packets on the wire to 10.0.0.1.
	sixToFour = netip.MustParsePrefix("2002::/16")
	// RFC 4291's deprecated IPv4-compatible form. Deprecated is not the same
	// as unroutable, and ::a00:1 is 10.0.0.1.
	v4Compatible = netip.MustParsePrefix("::/96")
)

// embeddedV4 returns the IPv4 address a v6 address carries, if it carries one.
func embeddedV4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64WellKnown.Contains(a), v4Compatible.Contains(a):
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}), true
	}
	return netip.Addr{}, false
}

// isUnsafeResolvedAddr reports whether a is somewhere a legitimate public
// allowlisted domain should never resolve to.
func isUnsafeResolvedAddr(a netip.Addr) bool {
	// Unmap first: ::ffff:169.254.169.254 and 169.254.169.254 are the same
	// destination, and a table of v4 prefixes does not match the v6 spelling.
	//
	// Then drop the zone, which is not a detail. netip.Prefix.Contains returns
	// FALSE for any address carrying a zone, because prefixes have none — so
	// fe80::1%eth0, which is exactly the shape a link-local resolution takes,
	// would walk through every entry below untouched. A check that fails open
	// on the one range it was written for is worse than no check.
	a = a.Unmap().WithZone("")
	if !a.IsValid() {
		return true // unparseable is not dialable; fail closed
	}
	if v4, ok := embeddedV4(a); ok {
		// One level deep and no further: embeddedV4 only ever returns an IPv4
		// address, and an IPv4 address carries nothing inside it.
		return isUnsafeResolvedAddr(v4)
	}
	for _, p := range unsafePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// refuseUnsafeResolvedAddr builds a net.Dialer.Control hook for one dial's
// original hostname, so the error it returns can name that hostname as well
// as the address. address is already the numeric ip:port about to be
// connected to — resolution is done — so returning an error here stops the
// dial before the connect syscall runs; nothing has been sent and nothing has
// been read.
func refuseUnsafeResolvedAddr(host string) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ipStr, _, err := net.SplitHostPort(address)
		if err != nil {
			ipStr = address
		}
		a, err := netip.ParseAddr(ipStr)
		if err != nil {
			return fmt.Errorf("resolved address %q is not an IP", ipStr)
		}
		// Normalised once, here, and it is the normalised form that is
		// recorded. netip.ParseAddr accepts an arbitrary zone —
		// "fe80::1%<script>alert(1)</script>" parses and round-trips through
		// String() verbatim — and what this returns is written to the flight
		// recorder as the attempt's resolved_addr. Nothing reaches it today,
		// since a resolver is what supplies this address and allowsHost has
		// already matched the name against the operator's own list, so this is
		// latent rather than live. Recording the stripped form costs one line
		// and means the record holds an address literal and nothing else.
		a = a.Unmap().WithZone("")
		if isUnsafeResolvedAddr(a) {
			return &errUnsafeResolvedAddr{host: host, addr: a.String()}
		}
		return nil
	}
}

// dialerFor returns the *net.Dialer that should open a connection to host.
// When host is already a literal IP address, nothing is resolved, so there
// is nothing for the Control hook to check; when it is a name, Control
// validates every address the resolver hands back, immediately before each
// one is dialled.
func dialerFor(host string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if net.ParseIP(host) == nil {
		d.Control = refuseUnsafeResolvedAddr(host)
	}
	return d
}

// dialContextSafe is the DialContext shared by every egress http.Transport
// (terminatedTransport and forwardTransport): addr is "host:port" exactly as
// the request named it, ahead of the transport's own resolution, so
// dialerFor's literal-IP exemption still applies from here too.
func dialContextSafe(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return dialerFor(host, 0).DialContext(ctx, network, addr)
}

// reportDialFailure records and answers a failed upstream dial, telling a
// resolved-address refusal (F2) apart from an ordinary network failure so the
// guest and the flight recorder both say which one happened. Shared by
// tunnel, terminate's upstream leg and forwardHTTP — the three places a
// failed dial is reported.
func (p *Proxy) reportDialFailure(w io.Writer, host string, port int, err error) {
	var unsafe *errUnsafeResolvedAddr
	if errors.As(err, &unsafe) {
		// The address goes to the recorder and the denial goes to the guest,
		// and they no longer say the same thing. A guest that is told which
		// address an allowlisted name resolves to has been handed the result
		// of a DNS lookup it has no resolver of its own to perform — one name
		// at a time, that is a map of the host's network. The operator needs
		// the address, so it is in the chain (F14).
		p.report(Attempt{Host: host, Port: port, Reason: ReasonUnsafeResolvedAddr,
			ResolvedAddr: unsafe.addr})
		writeStatus(w, http.StatusForbidden, "kelyfos: "+
			denial.EgressResolvedAddr.Render(denial.V{"host": host}))
		return
	}
	p.report(Attempt{Host: host, Port: port, Reason: ReasonDialFailed})
	writeStatus(w, http.StatusBadGateway, "kelyfos: "+err.Error())
}

// forwardTransport is what forwardHTTP fetches through: a plain-HTTP
// request, and an absolute-form https:// request that reached this proxy
// without a CONNECT first (ModeDirectTLS, S5d). A clone of
// http.DefaultTransport, not the package var itself, with DialContext
// replaced by the same resolved-address check every other egress dial path
// uses (F2) — this function shared tunnel's and terminate's exposure to the
// gap until now, since nothing about a plain or direct-TLS request ever
// validated where its name actually resolved to before dialling it.
//
// A var, not a literal call at each request, so a test can still swap it for
// the length of one test to trust a self-signed certificate — the same
// purpose http.DefaultTransport was swapped for before this change gave
// forwardHTTP a transport of its own to swap instead.
var forwardTransport http.RoundTripper = newForwardTransport()

func newForwardTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = dialContextSafe
	return t
}
