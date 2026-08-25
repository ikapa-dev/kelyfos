package egress

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "ghp_thisisaverysecrettokenvalue"

// proxyFor starts a proxy in front of an upstream test server, with the given
// policy, and returns its address plus everything it reported.
func proxyFor(t *testing.T, upstream *httptest.Server, policy Policy, ca *CA) (string, func() []Attempt, func() []string, func() []string, func() []string) {
	t.Helper()

	var mu sync.Mutex
	var attempts []Attempt
	var secrets []string
	var withheld []string
	var scrubbed []string

	p := &Proxy{
		Policy: policy,
		CA:     ca,
		// The test server has a self-signed certificate of its own; the proxy
		// validating it properly is the point of the upstream leg.
		Upstream: upstream.Client().Transport,
		OnEvent: func(a Attempt) {
			mu.Lock()
			defer mu.Unlock()
			attempts = append(attempts, a)
		},
		OnSecret: func(name, host string) {
			mu.Lock()
			defer mu.Unlock()
			secrets = append(secrets, name+"@"+host)
		},
		OnScrubbed: func(name, host string) {
			mu.Lock()
			defer mu.Unlock()
			scrubbed = append(scrubbed, name+"@"+host)
		},
		OnWithheld: func(name, host, reason string) {
			mu.Lock()
			defer mu.Unlock()
			withheld = append(withheld, name+"@"+host+":"+reason)
		},
	}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	return fmt.Sprintf("127.0.0.1:%d", port),
		func() []Attempt {
			mu.Lock()
			defer mu.Unlock()
			return append([]Attempt(nil), attempts...)
		},
		func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), secrets...)
		},
		func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), withheld...)
		},
		func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), scrubbed...)
		}
}

// throughProxy performs an HTTPS GET through the proxy's CONNECT, trusting the
// given roots for the inner TLS session. It returns the raw client connection
// as well: a tunnelled attempt is only recorded once both copy directions end,
// and the client-to-upstream direction ends when the client closes, so a test
// that wants to see that record has to close it first.
func throughProxy(t *testing.T, proxyAddr, target string, roots *x509.CertPool) (*http.Response, net.Conn, error) {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { raw.Close() })

	host, _, _ := net.SplitHostPort(target)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	if !strings.Contains(line, "200") {
		body, _ := io.ReadAll(br)
		return nil, nil, fmt.Errorf("proxy refused: %s%s", strings.TrimSpace(line), body)
	}
	for { // drain the rest of the response headers
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, nil, err
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}

	inner := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots})
	if err := inner.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("inner handshake: %w", err)
	}
	fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostHeader(host))
	resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
	return resp, raw, err
}

// hostHeaderOverride lets one test address the inner request to a name other
// than the one it opened the tunnel to. Package-level rather than a parameter
// so the existing callers stay unchanged.
var hostHeaderOverride string

func hostHeader(connectHost string) string {
	if hostHeaderOverride != "" {
		return hostHeaderOverride
	}
	return connectHost
}

// TestTerminationInjectsTheCredential is the heart of P2-6: the client is never
// given the secret, and the server receives it anyway.
func TestTerminationInjectsTheCredential(t *testing.T) {
	// Observed server-side rather than echoed back in the body, which is how
	// this test used to read it. P6-5 made that impossible on purpose: a server
	// that reflects a bound credential now has it scrubbed on the way to the
	// guest, and the first thing echo suppression caught was this test.
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}

	proxyAddr, attempts, secretUses, _, _ := proxyFor(t, upstream, policy, ca)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	target := strings.TrimPrefix(upstream.URL, "https://")
	resp, _, err := throughProxy(t, proxyAddr, target, roots)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	resp.Body.Close()

	if got, want := sawAuth, "Bearer "+testToken; got != want {
		t.Errorf("the upstream server saw Authorization %q, want %q", got, want)
	}

	// The connection must be recorded as terminated, so a user can tell which
	// traffic the proxy could read.
	recorded := waitForAttempt(t, attempts, func(a Attempt) bool {
		return a.Allowed && a.Mode == ModeTerminated
	})
	for _, a := range recorded {
		if a.Mode == ModeTunnelled {
			t.Errorf("a secret-bound domain must be terminated, not tunnelled: %+v", a)
		}
	}
	if uses := secretUses(); len(uses) == 0 || !strings.HasPrefix(uses[0], "GITHUB_TOKEN@") {
		t.Errorf("secret use was not reported by name: %v", uses)
	}
}

// A domain with no secret must be tunnelled, so the proxy sees plaintext for
// exactly the domains a credential was bound to (decision D6).
func TestNoSecretMeansNoTermination(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}}
	proxyAddr, attempts, _, _, _ := proxyFor(t, upstream, policy, nil)

	// No KelyfOS CA anywhere: the client validates the real server certificate,
	// which only works because nothing is in the middle.
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	resp, raw, err := throughProxy(t, proxyAddr, strings.TrimPrefix(upstream.URL, "https://"), roots)
	if err != nil {
		t.Fatalf("tunnelled request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" {
		t.Errorf("tunnelled body = %q", body)
	}
	// A tunnel's record is written once both copy directions end, and the
	// client-to-upstream direction ends when the client hangs up. Nothing is
	// recorded until then, by design: the record carries the byte counts.
	raw.Close()
	// Wait for the connection's own record before asserting anything about it.
	// Checking too early would let this test pass by finding nothing at all,
	// which is the one result it must never accept.
	for _, a := range waitForAttempt(t, attempts, func(a Attempt) bool {
		return a.Allowed && a.Mode == ModeTunnelled
	}) {
		if a.Mode == ModeTerminated {
			t.Errorf("a domain with no secret must not be terminated: %+v", a)
		}
	}
}

// waitForAttempt blocks until the proxy has recorded a matching attempt, and
// returns everything recorded so far.
//
// The wait is not politeness, it is correctness. An attempt is reported when the
// connection finishes, which is deliberately after the last byte has reached the
// client: the record carries the byte counts, so it cannot be written before
// there are any to count. A test that reads the response body and immediately
// inspects the record is therefore racing the proxy's own bookkeeping — and it
// loses about one run in ten, which is exactly often enough to be dismissed as
// noise and exactly rare enough to survive review.
func waitForAttempt(t *testing.T, attempts func() []Attempt, match func(Attempt) bool) []Attempt {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := attempts()
		for _, a := range got {
			if match(a) {
				return got
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching attempt was recorded within 5s: %+v", got)
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The value must not be reachable through the ordinary ways a Go value ends up
// in a log line.
func TestSecretValueNeverFormats(t *testing.T) {
	s := &Secret{Name: "GITHUB_TOKEN", Domain: "github.com", Scheme: "Bearer", value: testToken}
	for _, rendered := range []string{
		fmt.Sprintf("%v", s), fmt.Sprintf("%s", s), fmt.Sprintf("%+v", s), s.String(),
	} {
		if strings.Contains(rendered, testToken) {
			t.Errorf("a Secret rendered its value: %s", rendered)
		}
	}
	// Only the deliberate accessor exposes it.
	if !strings.Contains(s.Header(), testToken) {
		t.Error("Header() must carry the value")
	}
}

func upstreamPort(t *testing.T, s *httptest.Server) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(strings.TrimPrefix(s.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// A guest must not be able to have the credential presented to a name other
// than the one the connection was opened, verified and recorded against.
//
// This was a live defect rather than a new rule. http.ReadRequest fills
// req.Host from the guest's own Host: header, and Go's Request.write prefers
// req.Host over req.URL.Host — so the proxy setting the URL host did not change
// the header on the wire. The request was dialled to the bound domain and its
// certificate verified there, and then carried whatever Host the guest liked.
// On a virtual-hosted or shared-edge origin that routes on Host, that is the
// bound credential presented to a different site; and the record named the
// CONNECT target, so it said the wrong thing too.
func TestTheCredentialIsWithheldWhenTheRequestAddressesAnotherHost(t *testing.T) {
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}

	proxyAddr, _, secretUses, withheld, _ := proxyFor(t, upstream, policy, ca)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	// Open the tunnel to the bound host, then address the inner request
	// somewhere else entirely.
	hostHeaderOverride = "another-tenant.example"
	t.Cleanup(func() { hostHeaderOverride = "" })

	target := strings.TrimPrefix(upstream.URL, "https://")
	resp, _, err := throughProxy(t, proxyAddr, target, roots)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	resp.Body.Close()

	if sawAuth != "" {
		t.Errorf("the credential was attached to a request addressed to %q: Authorization %q",
			hostHeaderOverride, sawAuth)
	}
	if uses := secretUses(); len(uses) != 0 {
		t.Errorf("secret.use was reported for a request that never carried the credential: %v", uses)
	}
	got := withheld()
	if len(got) == 0 {
		t.Fatal("the credential was withheld and nothing said so — the silent failure this event exists to prevent")
	}
	if !strings.HasSuffix(got[0], ":"+WithheldHostMismatch) {
		t.Errorf("withheld for %q, want reason %q", got[0], WithheldHostMismatch)
	}
}

// A server that hands the credential back gets it replaced before the guest
// sees it — the one case construction cannot reach, because the value travels
// in a direction KelyfOS did not put it in (P6-5, D37).
func TestAnEchoedCredentialNeverReachesTheGuest(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The plainest echo there is: a server quoting back the credential it
		// rejected, in a header and in the body.
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		fmt.Fprintf(w, `{"error":"bad credential %s"}`, testToken)
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}

	proxyAddr, _, _, _, scrubbed := proxyFor(t, upstream, policy, ca)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	resp, _, err := throughProxy(t, proxyAddr, strings.TrimPrefix(upstream.URL, "https://"), roots)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if strings.Contains(string(body), testToken) {
		t.Errorf("the credential came back to the guest in the body: %s", body)
	}
	if strings.Contains(resp.Header.Get("X-Echo"), testToken) {
		t.Errorf("the credential came back to the guest in a header: %q", resp.Header.Get("X-Echo"))
	}
	// The length must not move, or a keep-alive connection desyncs.
	if want := len(fmt.Sprintf(`{"error":"bad credential %s"}`, testToken)); len(body) != want {
		t.Errorf("the body length changed from %d to %d", want, len(body))
	}
	if got := scrubbed(); len(got) == 0 {
		t.Error("bytes were altered on the way to the guest and the record does not say so")
	} else if !strings.HasPrefix(got[0], "GITHUB_TOKEN@") {
		t.Errorf("the scrub was recorded as %q, want it named by secret", got[0])
	}
}

// A peer that reads the request and then resets the connection already has the
// credential — only the answer is missing. secret.use used to be written after
// the round trip returned, so that request produced no record at all and
// nothing on the machine said the token had left it (L-1).
//
// The event's own documented meaning is attachment, not delivery, so the
// silence was a contradiction of the schema as well as a gap in the record.
func TestACredentialThePeerTookIsRecordedWhenTheConnectionIsReset(t *testing.T) {
	var mu sync.Mutex
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = r.Header.Get("Authorization")
		mu.Unlock()
		// The handler runs only once the request has been read, so whatever it
		// saw is provably on the wire. Reset instead of answering: SO_LINGER 0
		// turns Close into an RST rather than a FIN, which is what a peer under
		// load does to a connection it is not going to serve.
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		if tc, ok := conn.(*tls.Conn); ok {
			if raw, ok := tc.NetConn().(*net.TCPConn); ok {
				_ = raw.SetLinger(0)
			}
		}
		conn.Close()
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}

	proxyAddr, attempts, secretUses, _, _ := proxyFor(t, upstream, policy, ca)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	resp, _, err := throughProxy(t, proxyAddr, strings.TrimPrefix(upstream.URL, "https://"), roots)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	resp.Body.Close()

	// The failure is only interesting if the credential really did leave. If
	// the peer never saw it this test is proving nothing.
	mu.Lock()
	got := sawAuth
	mu.Unlock()
	if want := "Bearer " + testToken; got != want {
		t.Fatalf("the peer saw Authorization %q, want %q — the reset came too early to test anything", got, want)
	}

	// The upstream failure is reported after the credential is, so waiting for
	// it means a missing secret.use is a real absence rather than a race.
	waitForAttempt(t, attempts, func(a Attempt) bool { return a.Reason == ReasonDialFailed })

	uses := secretUses()
	if len(uses) == 0 {
		t.Fatal("the credential reached the peer and the record does not mention it")
	}
	if uses[0] != "GITHUB_TOKEN@"+host {
		t.Errorf("secret use recorded as %q, want %q", uses[0], "GITHUB_TOKEN@"+host)
	}
}

// The other half of the same branch, and the reason the fix cannot simply
// report on every round-trip error: when the connection is never established
// no byte of the credential leaves, and a record claiming otherwise would say
// a token was presented to a host that never heard from us.
func TestNoCredentialIsRecordedWhenTheRequestNeverLeftTheHost(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the upstream was supposed to be gone before anything dialled it")
	}))
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}

	proxyAddr, attempts, secretUses, _, _ := proxyFor(t, upstream, policy, ca)

	// Take the port away now that the proxy holds a transport pointed at it.
	// The policy still names the host, so the CONNECT and the inner handshake
	// both succeed and the failure lands exactly where it is wanted: on the
	// upstream dial, before a request has been written.
	upstream.Close()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	resp, _, err := throughProxy(t, proxyAddr, host+":"+fmt.Sprint(upstreamPort(t, upstream)), roots)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	resp.Body.Close()

	waitForAttempt(t, attempts, func(a Attempt) bool { return a.Reason == ReasonDialFailed })
	if uses := secretUses(); len(uses) != 0 {
		t.Errorf("secret.use was recorded for a request that never went out: %v", uses)
	}
}
