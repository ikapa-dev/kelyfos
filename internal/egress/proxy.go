// Package egress implements the KelyfOS egress proxy: the only route from a
// sandbox to the network, and therefore the only place its policy has to be
// enforced.
//
// The guest reaches it through a point-to-point TAP whose nftables rules permit
// nothing else (docs/networking.md). It is not a filter the guest routes
// through — it is the door.
package egress

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Modes recorded per allowed connection (decision D6).
const (
	ModeTunnelled  = "tunnelled"
	ModeTerminated = "terminated"
)

// Reasons recorded when a connection is refused.
const (
	ReasonNotAllowed = "not_in_allowlist"
	ReasonBadPort    = "port_not_allowed"
	ReasonBadRequest = "bad_request"
	ReasonDialFailed = "upstream_unreachable"
	ReasonPinned     = "tls_pinning_rejected_our_ca"
)

// Attempt is one outbound connection, reported to the caller's recorder whether
// it was permitted or not. A blocked attempt is the interesting one.
type Attempt struct {
	Host     string
	Port     int
	Allowed  bool
	Reason   string
	Mode     string
	BytesIn  int64
	BytesOut int64
}

// Policy decides what may leave.
type Policy struct {
	// Allow lists permitted hostnames. A bare hostname matches itself and its
	// subdomains, so "github.com" also permits "api.github.com" — which is what
	// someone typing --allow github.com means, and refusing it would only teach
	// them to pass a wildcard.
	Allow []string
	// Ports that may be reached. Empty means 80 and 443.
	Ports []int
	// Secrets bound to domains. A domain with a secret is TLS-terminated so the
	// credential can be attached; every other domain is tunnelled untouched
	// (decision D6).
	Secrets []*Secret
}

func (p *Policy) allowsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range p.Allow {
		a = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(a, "."), "*."))
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func (p *Policy) allowsPort(port int) bool {
	if len(p.Ports) == 0 {
		return port == 80 || port == 443
	}
	for _, allowed := range p.Ports {
		if port == allowed {
			return true
		}
	}
	return false
}

// Proxy is an HTTP proxy that enforces a Policy and reports every attempt.
type Proxy struct {
	Policy  Policy
	OnEvent func(Attempt)
	// OnSecret is called with the secret's NAME and the host it went to —
	// never the value, in any form (docs/events.md §4).
	OnSecret func(name, host string)
	// CA terminates TLS for secret-bound domains. Ephemeral, per run.
	CA *CA
	// Upstream is the transport used for terminated requests. Injectable so
	// tests can point it at a local server.
	Upstream http.RoundTripper

	// DialTimeout bounds how long an upstream connection may take to establish.
	DialTimeout time.Duration

	ln   net.Listener
	wg   sync.WaitGroup
	once sync.Once
}

// Listen binds the proxy. The address is the host's TAP address, so the proxy
// is reachable from exactly one sandbox and from nothing else on the machine.
func (p *Proxy) Listen(addr string) (int, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("bind egress proxy on %s: %w", addr, err)
	}
	p.ln = ln
	if p.DialTimeout == 0 {
		p.DialTimeout = 15 * time.Second
	}
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Serve accepts until Close.
func (p *Proxy) Serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(conn)
		}()
	}
}

func (p *Proxy) Close() {
	p.once.Do(func() {
		if p.ln != nil {
			_ = p.ln.Close()
		}
	})
	p.wg.Wait()
}

func (p *Proxy) report(a Attempt) {
	if p.OnEvent != nil {
		p.OnEvent(a)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)

	req, err := http.ReadRequest(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			p.report(Attempt{Reason: ReasonBadRequest})
		}
		return
	}

	host, port, err := splitTarget(req)
	if err != nil {
		p.report(Attempt{Reason: ReasonBadRequest})
		writeStatus(client, http.StatusBadRequest, "kelyfos: "+err.Error())
		return
	}

	switch {
	case !p.Policy.allowsHost(host):
		p.report(Attempt{Host: host, Port: port, Reason: ReasonNotAllowed})
		writeStatus(client, http.StatusForbidden,
			"kelyfos: "+host+" is not in this sandbox's allowlist")
		return
	case !p.Policy.allowsPort(port):
		p.report(Attempt{Host: host, Port: port, Reason: ReasonBadPort})
		writeStatus(client, http.StatusForbidden,
			fmt.Sprintf("kelyfos: port %d is not permitted", port))
		return
	}

	if req.Method == http.MethodConnect {
		// Terminate only when a secret is bound to this domain. Everything else
		// is tunnelled untouched, so the proxy sees plaintext for exactly the
		// domains the user handed a credential to (decision D6).
		if secret := p.Policy.secretFor(host); secret != nil {
			p.terminate(client, host, port, secret)
			return
		}
		p.tunnel(client, host, port)
		return
	}
	p.forwardHTTP(client, req, host, port)
}

// tunnel handles CONNECT: the proxy never sees inside the connection, and says
// so in the event it records.
func (p *Proxy) tunnel(client net.Conn, host string, port int) {
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), p.DialTimeout)
	if err != nil {
		p.report(Attempt{Host: host, Port: port, Reason: ReasonDialFailed})
		writeStatus(client, http.StatusBadGateway, "kelyfos: "+err.Error())
		return
	}
	defer upstream.Close()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	var in, out int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); out, _ = io.Copy(upstream, client); halfClose(upstream) }()
	go func() { defer wg.Done(); in, _ = io.Copy(client, upstream); halfClose(client) }()
	wg.Wait()

	p.report(Attempt{
		Host: host, Port: port, Allowed: true, Mode: ModeTunnelled,
		BytesOut: out, BytesIn: in,
	})
}

// forwardHTTP handles a plain (non-CONNECT) proxied request.
func (p *Proxy) forwardHTTP(client net.Conn, req *http.Request, host string, port int) {
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		p.report(Attempt{Host: host, Port: port, Reason: ReasonDialFailed})
		writeStatus(client, http.StatusBadGateway, "kelyfos: "+err.Error())
		return
	}
	defer resp.Body.Close()
	_ = resp.Write(client)
	p.report(Attempt{Host: host, Port: port, Allowed: true, Mode: ModeTunnelled})
}

func splitTarget(req *http.Request) (string, int, error) {
	target := req.Host
	if req.Method == http.MethodConnect {
		target = req.URL.Host
		if target == "" {
			target = req.Host
		}
	} else if req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
	}
	if target == "" {
		return "", 0, errors.New("request has no host")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		if req.Method == http.MethodConnect || req.URL.Scheme == "https" {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	return strings.ToLower(host), port, nil
}

func writeStatus(w io.Writer, code int, body string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body)+1, body+"\n")
}

func halfClose(c net.Conn) {
	if h, ok := c.(interface{ CloseWrite() error }); ok {
		_ = h.CloseWrite()
	}
}
