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
	"sync/atomic"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/denial"
)

// Modes recorded per allowed connection (decision D6).
// How much of a connection the proxy could read, recorded on every allowed
// attempt. D6's binding condition (2) is that a user can always prove which
// traffic the proxy was able to see, and that only works if the value never
// understates it.
const (
	// ModeTunnelled: a CONNECT relayed without being opened. The proxy moved
	// bytes it could not read.
	ModeTunnelled = "tunnelled"
	// ModeTerminated: a secret is bound to this domain, so the proxy decrypted
	// the session to attach the credential and saw the plaintext.
	ModeTerminated = "terminated"
	// ModePlain: an ordinary HTTP request, which the proxy necessarily parsed,
	// rewrote and re-issued. Nothing was decrypted because nothing was
	// encrypted — and the proxy still read all of it. Recording this as
	// tunnelled was the one place the audit log understated the host's own
	// visibility (F-D33).
	ModePlain = "plain"
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
		a = NormaliseDomain(a)
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
	// OnWithheld is the counterpart: a credential was bound to this domain and
	// deliberately not attached, with the reason. It is the more useful of the
	// two when something is wrong — a credential that silently does not attach
	// sends the request out unauthenticated, and the only symptom is a failure
	// from somewhere else. Name and host only, like OnSecret; never a value and
	// never a request path, because a path is a credential on more APIs than is
	// comfortable (docs/events.md §4).
	OnWithheld func(name, host, reason string)
	// OnScrubbed says the proxy altered bytes on their way to the guest: a
	// response echoed a bound credential back and it was replaced. Recorded
	// because a proxy that rewrites a byte stream and says nothing is a proxy
	// whose record understates what the host did (P6-5).
	OnScrubbed func(name, host string)
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

	// lastActive is the last moment any byte crossed this proxy, in Unix
	// nanoseconds. It exists for the idle timeout (E1-6): a sandbox pulling a
	// large file down a tunnel is not idle, and reporting only completed
	// attempts would say it was for as long as the transfer lasted.
	lastActive atomic.Int64
}

// touch records that the sandbox is doing something.
func (p *Proxy) touch() { p.lastActive.Store(time.Now().UnixNano()) }

// LastActive reports when a byte last crossed the proxy, or the zero time if
// nothing ever has.
func (p *Proxy) LastActive() time.Time {
	if n := p.lastActive.Load(); n != 0 {
		return time.Unix(0, n)
	}
	return time.Time{}
}

// activeWriter marks the proxy busy as bytes move through it. Wrapping the
// writer rather than the reader means the timestamp advances when data is
// actually delivered, not merely when it is available to read.
type activeWriter struct {
	w io.Writer
	p *Proxy
}

func (a activeWriter) Write(b []byte) (int, error) {
	a.p.touch()
	return a.w.Write(b)
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
	p.touch()
	if p.OnEvent != nil {
		p.OnEvent(a)
	}
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	p.touch()
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
		// The fix line goes to the guest, which is where it is needed: this
		// body is what curl prints and what an agent reads back (E5-4).
		writeStatus(client, http.StatusForbidden,
			"kelyfos: "+denial.EgressHost.Render(denial.V{"host": host}))
		return
	case !p.Policy.allowsPort(port):
		p.report(Attempt{Host: host, Port: port, Reason: ReasonBadPort})
		writeStatus(client, http.StatusForbidden,
			"kelyfos: "+denial.EgressPort.Render(denial.V{
				"host": host, "port": strconv.Itoa(port)}))
		return
	}

	if req.Method == http.MethodConnect {
		// Terminate only when a secret is bound to this domain. Everything else
		// is tunnelled untouched, so the proxy sees plaintext for exactly the
		// domains the user handed a credential to (decision D6).
		if bound := p.Policy.secretsFor(host); len(bound) > 0 {
			p.terminate(client, host, port, bound)
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
	go func() {
		defer wg.Done()
		out, _ = io.Copy(activeWriter{upstream, p}, client)
		halfClose(upstream)
	}()
	go func() {
		defer wg.Done()
		in, _ = io.Copy(activeWriter{client, p}, upstream)
		halfClose(client)
	}()
	wg.Wait()

	p.report(Attempt{
		Host: host, Port: port, Allowed: true, Mode: ModeTunnelled,
		BytesOut: out, BytesIn: in,
	})
}

// forwardHTTP handles a plain (non-CONNECT) proxied request.
func (p *Proxy) forwardHTTP(client net.Conn, req *http.Request, host string, port int) {
	// A credential is never attached to a plaintext request, and never has
	// been: injection lives on the terminated path alone. That is right —
	// nobody should put a bearer token on an unencrypted request — but it had
	// never been said anywhere, so a user who bound a secret and then reached
	// the domain over http:// got an unauthenticated request and no reason for
	// it. Now the record gives the reason (P6-4).
	if bound := p.Policy.secretsFor(host); len(bound) > 0 && p.OnWithheld != nil {
		p.OnWithheld(bound[0].Name, host, WithheldUnencrypted)
	}
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
	p.scrubResponse(resp, host)
	// Counted rather than left at zero: this path moved bytes like any other,
	// and a receipt that reads 0 for a transfer that happened is its own small
	// lie. ContentLength is -1 for a chunked body, which is not a byte count,
	// so an unknown length is recorded as unknown.
	var out, in int64
	if req.ContentLength > 0 {
		out = req.ContentLength
	}
	counted := &countingReader{r: resp.Body}
	resp.Body = counted
	_ = resp.Write(client)
	in = counted.n
	p.report(Attempt{Host: host, Port: port, Allowed: true, Mode: ModePlain,
		BytesOut: out, BytesIn: in})
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
	// net.SplitHostPort splits on the last colon and does not check that what
	// follows is a port, so `host:99999` parses and Atoi accepts it. The
	// connection would be refused downstream — allowsPort permits 80 and 443
	// and nothing else — but the number reaches the flight recorder first, and
	// a record that says a guest tried to reach port 99999 is a record saying
	// something that is not a port. Found by FuzzSplitTarget (P6-3).
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("bad port %q", portStr)
	}
	host = strings.ToLower(host)
	if !plausibleHost(host) {
		return "", 0, fmt.Errorf("bad host %q", host)
	}
	return host, port, nil
}

// plausibleHost reports whether a string can be a host at all.
//
// This is an allowlist of characters rather than a list of forbidden ones,
// because of what happens next: whatever comes back from splitTarget is the
// string the allowlist is asked about, the string a bound credential is matched
// against, and the string written into the flight recorder as the destination.
// A `Host: /` header used to produce the host `/`, which was then compared
// against an allowlist, refused, and recorded as somewhere a guest tried to
// reach. Nothing escaped — but a refusal naming a destination that is not a
// destination is the record saying something untrue, and the check costs a
// loop. Found by FuzzSplitTarget (P6-3).
//
// Letters, digits, `-`, `.` and `_` cover DNS names; `:` covers an IPv6 literal,
// which SplitHostPort has already unbracketed. Anything else is refused loudly
// with the offending string quoted, which is diagnosable in a way that a silent
// policy check on garbage is not.
func plausibleHost(host string) bool {
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == ':':
		default:
			return false
		}
	}
	return true
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

// countingReader counts what passes through it, so a plain-HTTP transfer has a
// byte count like every other kind.
type countingReader struct {
	r io.ReadCloser
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }
