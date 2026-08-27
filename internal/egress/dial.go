package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
// name's resolved address is loopback, link-local (169.254.0.0/16 — cloud
// instance metadata — included), or otherwise private/reserved space: not
// somewhere a legitimate public allowlisted domain has any business
// resolving to. Carries the address, so the caller can name it in what it
// tells the guest and what it writes to the flight recorder.
type errUnsafeResolvedAddr struct {
	host, addr string
}

func (e *errUnsafeResolvedAddr) Error() string {
	return fmt.Sprintf("%s resolved to %s, which this proxy refuses to dial", e.host, e.addr)
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
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("resolved address %q is not an IP", ipStr)
		}
		if isUnsafeResolvedIP(ip) {
			return &errUnsafeResolvedAddr{host: host, addr: ip.String()}
		}
		return nil
	}
}

// isUnsafeResolvedIP reports whether ip is somewhere a legitimate public
// allowlisted domain should never resolve to: loopback, link-local — which
// includes 169.254.169.254, the cloud instance metadata address this check
// exists for — or other private/reserved space.
func isUnsafeResolvedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsPrivate()
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
		p.report(Attempt{Host: host, Port: port, Reason: ReasonUnsafeResolvedAddr})
		writeStatus(w, http.StatusForbidden, "kelyfos: "+
			denial.EgressResolvedAddr.Render(denial.V{"host": host, "addr": unsafe.addr}))
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
