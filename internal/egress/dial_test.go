package egress

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// isUnsafeResolvedIP's own table, independent of any dial: the ranges F2
// exists for (loopback, link-local — 169.254.169.254, the cloud metadata
// address, specifically included — and other private/reserved space) must be
// refused, and ordinary public addresses must not be.
func TestIsUnsafeResolvedIP(t *testing.T) {
	unsafe := []string{
		"127.0.0.1", "127.0.0.53", "::1",
		"169.254.169.254", "169.254.1.1", "fe80::1",
		"10.0.0.5", "172.16.0.5", "192.168.1.1", "fc00::1",
		"0.0.0.0", "::",
		"224.0.0.1", "ff02::1",
	}
	// Same cases and same expectations as when this was written for F2; only
	// the argument type moved, from net.IP to netip.Addr, when the predicate
	// stack became a reviewable prefix table (F14).
	for _, s := range unsafe {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test bug: %q does not parse as an IP", s)
		}
		if !isUnsafeResolvedAddr(a) {
			t.Errorf("%s must be refused as an egress dial target, and was not", s)
		}
	}

	safe := []string{"93.184.216.34", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"}
	for _, s := range safe {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("test bug: %q does not parse as an IP", s)
		}
		if isUnsafeResolvedAddr(a) {
			t.Errorf("%s is a routable public address and must not be refused", s)
		}
	}
}

// dialerFor's literal-IP exemption: a host that is already an address was
// never resolved, so there is nothing for DNS to have hijacked, and every
// httptest.Server this package's own tests dial through is one of these
// (127.0.0.1). A host that is a name gets the check, because that is exactly
// what F2 is about.
func TestDialerForOnlyChecksHostnamesNotLiteralIPs(t *testing.T) {
	if d := dialerFor("127.0.0.1", 0); d.Control != nil {
		t.Error("a literal IP host must not carry the resolved-address Control hook")
	}
	if d := dialerFor("localhost", 0); d.Control == nil {
		t.Error("a hostname must carry the resolved-address Control hook")
	}
}

// The finding itself (F2): allowsHost and secretsFor decide purely on the
// hostname string a guest's CONNECT named — "localhost" is on the allowlist
// here — and neither ever looked at where that name actually resolves. Every
// environment this test runs in resolves "localhost" to loopback without any
// hosts-file edit, which is exactly the property a DNS-hijacked public
// domain would exhibit from the proxy's point of view: an allowlisted name
// resolving somewhere it must never be allowed to reach. The tunnel path
// (secretsFor(host) empty, no secret bound) must refuse the dial before ever
// touching the upstream — proven here by never starting one.
func TestTunnelRefusesAResolvedLoopbackAddressEvenWhenHostnameIsAllowlisted(t *testing.T) {
	// A listener that must never be dialled — its port is only used to build
	// a plausible target, and if anything ever connects the test would still
	// pass on the recorded reason, but nothing here accepts on it, so a
	// regression that dialled through would hang instead of quietly passing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
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
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(statusLine, "200") {
		t.Fatalf("a hostname resolving to loopback was tunnelled instead of refused: %q", statusLine)
	}

	var a Attempt
	select {
	case a = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no egress.attempt was recorded for the resolved-loopback CONNECT")
	}
	if a.Allowed {
		t.Fatalf("a resolved-loopback dial was recorded as allowed: %+v", a)
	}
	if a.Reason != ReasonUnsafeResolvedAddr {
		t.Errorf("reason = %q, want %q", a.Reason, ReasonUnsafeResolvedAddr)
	}
}

// The same finding, on forwardHTTP's path: a plain (non-CONNECT) request
// whose Host names an allowlisted domain that resolves to loopback must be
// refused by forwardTransport's DialContext, not fetched.
func TestForwardHTTPRefusesAResolvedLoopbackAddressEvenWhenHostnameIsAllowlisted(t *testing.T) {
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
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a hostname resolving to loopback was fetched instead of refused: %d", resp.StatusCode)
	}

	var a Attempt
	select {
	case a = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("no egress.attempt was recorded for the resolved-loopback GET")
	}
	if a.Allowed {
		t.Fatalf("a resolved-loopback dial was recorded as allowed: %+v", a)
	}
	if a.Reason != ReasonUnsafeResolvedAddr {
		t.Errorf("reason = %q, want %q", a.Reason, ReasonUnsafeResolvedAddr)
	}
}
