package egress

import (
	"context"
	"crypto/tls"
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

// upstreamDialTimeout bounds how long an egress transport waits for a TCP
// connection to an origin.
//
// It exists because there was no bound at all: dialContextSafe built its
// dialer with dialerFor(host, 0), neither transport supplies a dial timeout of
// its own, and the requests forwardHTTP re-issues carry context.Background —
// so an origin that accepted nothing held a goroutine and a socket until the
// kernel gave up, which on Linux is over two minutes. The same 15 seconds
// Proxy.DialTimeout already defaults to for the CONNECT tunnel and the
// terminated leg's own dial, so the three paths now agree (F15).
const upstreamDialTimeout = 15 * time.Second

// dialContextSafe is the DialContext shared by every egress http.Transport
// (terminatedTransport and forwardTransport): addr is "host:port" exactly as
// the request named it, ahead of the transport's own resolution, so
// dialerFor's literal-IP exemption still applies from here too.
func dialContextSafe(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return dialerFor(host, upstreamDialTimeout).DialContext(ctx, network, addr)
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
	// The address goes to the recorder and NOT into the answer, which is the
	// same rule the 403 above follows and the same reconnaissance F14 closed
	// there (P7-17/C). Go's own dial errors carry the resolved address —
	// `dial tcp 93.184.216.34:443: connect: connection refused` — so writing
	// err.Error() here handed the guest the result of a DNS lookup it has no
	// resolver of its own to perform, one allowlisted name at a time, on the
	// path that is reached by simply naming a host that does not answer.
	//
	// The message is fixed rather than summarised, because every shape of dial
	// failure this can carry names the address: refused, timed out, no route,
	// no such host. The address itself stays in the chain, in ResolvedAddr, for
	// the operator.
	p.report(Attempt{Host: host, Port: port, Reason: ReasonDialFailed,
		ResolvedAddr: dialFailureAddr(err), Detail: detailOf(err)})
	writeStatus(w, http.StatusBadGateway,
		"kelyfos: this proxy could not reach "+host+". Why is in the flight recorder and on "+
			"the operator's terminal; it is deliberately not here, because a failure message "+
			"names the address a name resolved to")
}

// dialFailureAddr digs the address out of a failed dial, for the recorder.
//
// net.OpError carries it as a structured field, so this reads the field rather
// than the message — the string is what must not reach the guest, and parsing
// it back out would be a second place for the same information to be spelled.
// Empty when the error is not a dial against an address, which is the case for
// a name that never resolved at all.
func dialFailureAddr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Addr != nil {
		return op.Addr.String()
	}
	return ""
}

// forwardTransport is what forwardHTTP fetches through: a plain-HTTP
// request, and an absolute-form https:// request that reached this proxy
// without a CONNECT first (ModeDirectTLS, S5d).
//
// A var, not a literal call at each request, so a test can still swap it for
// the length of one test to trust a self-signed certificate — the same
// purpose http.DefaultTransport was swapped for before this change gave
// forwardHTTP a transport of its own to swap instead.
var forwardTransport http.RoundTripper = newForwardTransport()

// newForwardTransport builds the transport field by field from a zero value.
//
// It used to be http.DefaultTransport.Clone(), and the field that clone
// carried and nobody looked at was Proxy: ProxyFromEnvironment. On any host
// with HTTPS_PROXY or HTTP_PROXY set — every corporate laptop — that sent the
// sandbox's plain-HTTP and direct-TLS traffic to the corporate proxy, and it
// was the corporate proxy that then resolved the name. dialContextSafe was
// still installed and still ran; it was simply handed the corporate proxy's
// address, so the resolved-address table never saw where the allowlisted name
// actually pointed. An allowlisted domain hijacked onto 169.254.169.254 was
// dialled by the upstream proxy, unchecked. The CONNECT tunnel and the
// terminated leg dial directly, so the behaviour differed by path with nothing
// saying so (F15).
//
// Building from a zero value rather than fixing Proxy alone is the point: a
// clone is not this transport, it is this transport plus whatever the standard
// library decides to add later, and Proxy is the field that already arrived
// that way. The cost is that everything the clone silently supplied has to be
// supplied deliberately — DefaultTransport's MaxIdleConns 100, IdleConnTimeout
// 90s and TLSHandshakeTimeout 10s are all zero on a zero value, and zero means
// "no limit" for the first three. Dropping them by omission would have traded a
// proxy leak for unbounded idle connections and a TLS handshake that can hang
// forever, which is why TestF15_BothEgressTransportsSetTheirOwnFields names
// each one. ExpectContinueTimeout is set below for a different reason, given
// at the field: zero there means no wait at all, not an unbounded one.
func newForwardTransport() *http.Transport {
	return &http.Transport{
		// Proxy is deliberately left nil, and this comment is the reason:
		// the egress proxy IS the proxy. It must never chain to one it did
		// not configure, and it must never inherit one from the environment
		// of whoever started the CLI (F15).
		Proxy: nil,
		// The resolved-address check, on this path as on every other (F2, F14).
		DialContext:     dialContextSafe,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		// HTTP/1.1 upstream. forwardHTTP writes the response it gets straight
		// back to the guest, and keeping one protocol on that leg keeps the
		// framing it re-emits the framing it received. Matches
		// terminatedTransport, which has always been explicit about this.
		ForceAttemptHTTP2: false,
		// The four DefaultTransport used to supply. Zero is unbounded for
		// the first three, so each is stated.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		// ExpectContinueTimeout is the exception to that sentence, and the
		// first version of this comment had it backwards. Go's own doc: zero
		// means no timeout "and causes the body to be sent immediately,
		// without waiting for the server to approve". Zero is the absence of a
		// wait, not an unbounded one. One second is right anyway — it is how
		// long to wait for a 100-continue before sending the body regardless —
		// but it is set for that reason and not to close a hole.
		ExpectContinueTimeout: 1 * time.Second,
		// And the one that was missing from "everything the clone silently
		// supplied", because DefaultTransport does not supply it either: an
		// origin that accepts the connection, completes TLS and then says
		// nothing holds a goroutine and a socket — and on the terminated leg
		// the credential with them — for as long as it likes. forwardHTTP
		// re-issues with context.Background, so no context covers this.
		//
		// The value is maxTerminatedIdleTotal and not the thirty seconds F15
		// first wrote (D74). Thirty seconds was never argued and never
		// documented, and it is below the time a non-streaming completion from
		// a model API legitimately takes to its first byte — which is the
		// traffic this proxy exists to broker.
		//
		// **On THIS transport it is the only bound on that wait**, and D74's
		// first version said otherwise (amended, P7-17/B2 review round). The
		// terminated leg has F16's machinery and this one has none: forwardHTTP
		// re-issues with context.Background, writes the response straight at
		// the client with no bodyClock, and handle has already cleared the read
		// deadline. So ten minutes here is a deliberate choice about how long an
		// allowlisted origin may hold a goroutine, two sockets and one of the
		// 128 connection slots — not a number some other bound was going to
		// enforce anyway.
		//
		// It still bounds only the wait for the first byte of the response
		// head. The body behind it is bounded on the terminated leg by the
		// rolling stall clock and, on this one, by nothing — which is stated
		// rather than implied, because the first version of this comment
		// borrowed the terminated leg's guarantee for both. Both transports
		// carry the same number, deliberately: a third bound nobody can hold in
		// their head is the shape this project has refused since the `jailed`
		// bug.
		ResponseHeaderTimeout: maxTerminatedIdleTotal,
	}
}
