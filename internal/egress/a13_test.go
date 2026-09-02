package egress

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// The audit of 2026-09-01's A13: the upstream transports were package-global,
// so their connection pools were shared by every proxy in the process. A
// connection dialled — and resolved-address-vetted — under one sandbox's
// policy could then serve another sandbox's request, skipping the per-dial
// resolved-address re-check the reuse makes unnecessary from the transport's
// point of view and mandatory from this one's. The transports are per proxy
// now, and this is the property that makes cross-proxy pool reuse impossible:
// two proxies hold two transports, and one proxy holds one.
func TestA13_EachProxyOwnsItsTransports(t *testing.T) {
	p1 := &Proxy{}
	p2 := &Proxy{}

	if p1.plainUpstream() == p2.plainUpstream() {
		t.Error("two proxies share the plain transport; their connection pools are shared too")
	}
	if p1.upstream() == p2.upstream() {
		t.Error("two proxies share the terminated transport; their connection pools are shared too")
	}
	// And the pool per proxy is still one pool: lazily built once, so
	// keep-alive works inside a sandbox the way it always did.
	if p1.plainUpstream() != p1.plainUpstream() {
		t.Error("one proxy rebuilt its plain transport between calls; its own keep-alive pool is gone")
	}
	if p1.upstream() != p1.upstream() {
		t.Error("one proxy rebuilt its terminated transport between calls; its own keep-alive pool is gone")
	}
}

// closeSpyRT is a RoundTripper that records that its idle connections were
// asked to close.
type closeSpyRT struct{ onClose func() }

func (r closeSpyRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("closeSpyRT does not round-trip")
}
func (r closeSpyRT) CloseIdleConnections() { r.onClose() }

// The audit of 2026-09-01's M11: Close closed the listener and nothing else, so
// up to MaxIdleConns vetted upstream sockets per proxy lingered to origins
// until their 90-second idle timer after the sandbox was gone. Close now drops
// both per-proxy transports' idle connections — and reads the fields directly,
// so a transport a proxy never built is not built here only to be closed.
func TestA13_CloseDropsBothTransportsIdleConnections(t *testing.T) {
	var terminatedClosed, plainClosed bool
	p := &Proxy{}
	p.terminatedRT = closeSpyRT{onClose: func() { terminatedClosed = true }}
	p.plainRT = closeSpyRT{onClose: func() { plainClosed = true }}
	p.Close()
	if !terminatedClosed {
		t.Error("Close did not drop the terminated transport's idle connections")
	}
	if !plainClosed {
		t.Error("Close did not drop the plain transport's idle connections")
	}

	// A transport this proxy never built must stay nil across Close, not be
	// constructed only to be closed.
	fresh := &Proxy{}
	fresh.Close()
	if fresh.terminatedRT != nil || fresh.plainRT != nil {
		t.Error("Close built a transport that was never used")
	}
}

// And end to end: a real idle upstream connection, pooled in a per-proxy
// transport, is actually ended by Close rather than left to time out.
func TestA13_CloseEndsTheIdleOriginConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	closed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Answer one request, keep the connection (keep-alive), then block on a
		// read until the peer closes it — which is what Close must cause.
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()

	// The proxy's own plain transport — a real *http.Transport with an idle
	// pool. A plain dialer, so the loopback origin is reachable: the
	// resolved-address guard newForwardTransport carries is orthogonal to what
	// this measures, which is that Close reaches the field and ends its pool.
	rt := &http.Transport{MaxIdleConns: 10, IdleConnTimeout: time.Minute}
	p := &Proxy{}
	p.plainRT = rt

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("priming request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// The connection is now idle in rt's pool. Until Close it stays open.
	select {
	case <-closed:
		t.Fatal("the origin connection closed before Close was called")
	case <-time.After(150 * time.Millisecond):
	}

	p.Close()

	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not end the idle origin connection")
	}
}
