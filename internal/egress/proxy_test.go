package egress

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAllowlistMatchesSubdomains(t *testing.T) {
	p := Policy{Allow: []string{"github.com", "pypi.org"}}
	for _, host := range []string{"github.com", "api.github.com", "raw.githubusercontent.com.github.com", "pypi.org"} {
		if !p.allowsHost(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
	// The near-misses that matter: a suffix match must not be a substring match,
	// or "notgithub.com" and "github.com.evil.net" would both sail through.
	for _, host := range []string{"notgithub.com", "github.com.evil.net", "evil.net", "githubXcom"} {
		if p.allowsHost(host) {
			t.Errorf("%s must NOT be allowed", host)
		}
	}
}

func TestAllowlistIsCaseAndDotInsensitive(t *testing.T) {
	p := Policy{Allow: []string{"GitHub.com."}}
	for _, host := range []string{"github.com", "API.GITHUB.COM", "github.com."} {
		if !p.allowsHost(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
}

func TestWildcardPrefixIsAccepted(t *testing.T) {
	// Someone will write it, and it should mean what they expect rather than
	// silently matching nothing.
	p := Policy{Allow: []string{"*.github.com"}}
	if !p.allowsHost("api.github.com") {
		t.Error("*.github.com should allow api.github.com")
	}
}

func TestEmptyAllowlistAllowsNothing(t *testing.T) {
	p := Policy{}
	if p.allowsHost("github.com") {
		t.Error("an empty allowlist must allow nothing")
	}
}

func TestDefaultPortsAreWebOnly(t *testing.T) {
	p := Policy{}
	for _, port := range []int{80, 443} {
		if !p.allowsPort(port) {
			t.Errorf("port %d should be allowed by default", port)
		}
	}
	for _, port := range []int{22, 25, 53, 8080, 6379} {
		if p.allowsPort(port) {
			t.Errorf("port %d must not be allowed by default", port)
		}
	}
}

// DefaultPorts is the named, exported fact every sandbox in this product
// actually runs on (P7-4). A change to it is a change to what every sandbox
// can reach, so this test exists to make that change loud rather than a
// one-line diff nobody reading the record would notice.
func TestDefaultPortsAreExactlyEightyAndFourFourThree(t *testing.T) {
	if got := DefaultPorts(); len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Errorf("DefaultPorts() = %v, want [80 443]", got)
	}
	// A fresh slice every call: mutating one caller's copy must never touch
	// another's, or the default itself.
	a, b := DefaultPorts(), DefaultPorts()
	a[0] = 9999
	if b[0] == 9999 {
		t.Error("DefaultPorts() shares a backing array across calls")
	}
}

// EffectivePorts is what P7-2's session.policy and P7-7/P7-8's views must
// read instead of Policy.Ports directly — Policy.Ports is nil for every
// sandbox this product has ever booted, and nil reads as "nothing permitted"
// rather than "the fixed default applies".
func TestEffectivePortsFallsBackToTheDefault(t *testing.T) {
	if got := (&Policy{}).EffectivePorts(); len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Errorf("an empty policy's EffectivePorts = %v, want DefaultPorts", got)
	}
	custom := []int{8443}
	if got := (&Policy{Ports: custom}).EffectivePorts(); len(got) != 1 || got[0] != 8443 {
		t.Errorf("a policy with its own Ports returned %v, want %v", got, custom)
	}
}

// D6's binding condition (2) is that a user can always prove which traffic the
// proxy was able to read. That only holds if the value never understates it,
// and for one path it did: an ordinary HTTP request is parsed, rewritten and
// re-issued by the proxy — it reads all of it — and was recorded as
// `tunnelled`, which is the word for a connection it could not read (F-D33).
func TestPlainHTTPIsNotRecordedAsTunnelled(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	// A channel rather than a slice: the proxy reports from its own goroutine
	// after the response has been written, so a test that reads a shared slice
	// the moment the client returns is racing it — and wins on a fast machine,
	// which is the worst way for a test to be wrong.
	attempts := make(chan Attempt, 4)
	p := &Proxy{Policy: Policy{Allow: []string{host}, Ports: []int{atoiOrZero(port)}}}
	p.OnEvent = func(a Attempt) { attempts <- a }
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", addr))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	var a Attempt
	select {
	case a = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy never reported the attempt")
	}
	if !a.Allowed {
		t.Fatalf("the request was refused: %+v", a)
	}
	if a.Mode == ModeTunnelled {
		t.Errorf("plain HTTP recorded as %q; the proxy read every byte of it, "+
			"and tunnelled is the word for a connection it could not read", a.Mode)
	}
	if a.Mode != ModePlain {
		t.Errorf("mode = %q, want %q", a.Mode, ModePlain)
	}
	if a.BytesIn <= 0 {
		t.Errorf("bytes_in = %d for a transfer that happened; a receipt reading zero "+
			"for real bytes is its own small lie", a.BytesIn)
	}
}

func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// A connection that never sends a request must not be held open forever: it
// costs a goroutine, a buffer and a slot in the concurrency cap for good.
// readHeaderTimeout is what closes it (S5a).
func TestConnectionWithNoRequestIsClosedByDeadline(t *testing.T) {
	p := &Proxy{}
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Generous over the production deadline rather than tight against it: the
	// property under test is "eventually closed", not "closed at exactly
	// readHeaderTimeout".
	if err := c.SetReadDeadline(time.Now().Add(readHeaderTimeout + 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("the connection was never closed for a request that never came")
	} else {
		t.Logf("closed with: %v", err)
	}
}

// http.ReadRequest has no ceiling of its own on how many bytes a request line
// and its headers may take. handle()'s headerLimitReader physically cannot
// hand it more than maxRequestHeaderBytes while parsing one, however large
// the guest's header block is — the request simply fails to parse, and that
// is refused exactly like any other request this proxy cannot make sense of
// (S5a). Not a plain io.LimitReader: see headerLimitReader's own comment for
// why one of those would truncate a legitimate request body instead.
func TestOversizedRequestHeadersAreRejected(t *testing.T) {
	attempts := make(chan Attempt, 4)
	p := &Proxy{}
	p.OnEvent = func(a Attempt) { attempts <- a }
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	huge := strings.Repeat("A", maxRequestHeaderBytes+(1<<20))
	raw := fmt.Sprintf("GET / HTTP/1.1\r\nHost: example.com\r\nX-Huge: %s\r\n\r\n", huge)
	go func() {
		// The proxy is expected to give up and close the connection before
		// this finishes; that failure is expected and ignored.
		_, _ = io.WriteString(c, raw)
	}()

	var a Attempt
	select {
	case a = <-attempts:
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy never reported the oversized request — it may be hanging trying to parse it")
	}
	if a.Allowed {
		t.Fatalf("an oversized request was allowed: %+v", a)
	}
	if a.Reason != ReasonBadRequest {
		t.Errorf("reason = %q, want %q", a.Reason, ReasonBadRequest)
	}
}

// headerLimitReader bounds header parsing, not the body a request goes on to
// stream afterward — a plain io.LimitReader shared between http.ReadRequest
// and req.Body does not know the difference, and a first version of the
// maxRequestHeaderBytes fix used one, silently truncating any plain-HTTP or
// direct-TLS request whose header and body together crossed 1 MiB. Found in
// review, before it shipped: a legitimate multi-megabyte upload is exactly
// the kind of thing a DoS-hardening change must not break.
func TestLargeRequestBodyIsForwardedIntact(t *testing.T) {
	const size = 3 << 20 // 3 MiB, well over maxRequestHeaderBytes (1 MiB)
	body := bytes.Repeat([]byte("x"), size)
	var received int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received = int(n)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	p := &Proxy{Policy: Policy{Allow: []string{host}, Ports: []int{atoiOrZero(portStr)}}}
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", addr))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Post(upstream.URL, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST through proxy: %v", err)
	}
	resp.Body.Close()

	if received != size {
		t.Fatalf("upstream received %d of %d bytes — the header size bound truncated the body", received, size)
	}
}

// maxConcurrentConnections bounds Serve, not merely handle: once every slot
// is held, Serve must block acquiring the next one rather than accepting a
// connection it has nowhere to put (S5a).
func TestConcurrentConnectionsAreCapped(t *testing.T) {
	release := make(chan struct{})
	inHandler := make(chan struct{}, maxConcurrentConnections+1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inHandler <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	p := &Proxy{Policy: Policy{Allow: []string{host}, Ports: []int{atoiOrZero(portStr)}}}
	addr, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	go p.Serve()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", addr))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Saturate every slot: each of these blocks inside the upstream handler
	// until release is closed.
	done := make(chan struct{}, maxConcurrentConnections)
	for i := 0; i < maxConcurrentConnections; i++ {
		go func() {
			resp, err := client.Get(upstream.URL)
			if err == nil {
				resp.Body.Close()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < maxConcurrentConnections; i++ {
		select {
		case <-inHandler:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d requests reached the upstream handler; "+
				"the proxy is not accepting up to its own cap", i, maxConcurrentConnections)
		}
	}

	// One more than the cap must not reach the handler while every slot is
	// held: Serve has nowhere to put it until one frees.
	extraDone := make(chan struct{}, 1)
	go func() {
		resp, err := client.Get(upstream.URL)
		if err == nil {
			resp.Body.Close()
		}
		extraDone <- struct{}{}
	}()
	select {
	case <-inHandler:
		t.Fatal("a connection past the cap reached the upstream handler before any slot was freed")
	case <-time.After(300 * time.Millisecond):
	}

	// Freeing exactly one slot lets the extra connection through.
	release <- struct{}{}
	select {
	case <-inHandler:
	case <-time.After(5 * time.Second):
		t.Fatal("the extra connection was never served after a slot freed")
	}
	close(release)
	for i := 0; i < maxConcurrentConnections; i++ {
		<-done
	}
	<-extraDone
}

// The genuinely plain case must not move: a bound secret reached over real
// plain HTTP is still withheld as WithheldUnencrypted and still recorded as
// ModePlain. Regression guard for S5d, which changes this function's
// behaviour only for an absolute-form https:// target.
func TestPlainHTTPWithheldReasonAndModeAreUnchanged(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))

	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{atoiOrZero(portStr)}, Secrets: []*Secret{secret}}
	proxyAddr, attempts, secretUses, withheld, _ := proxyFor(t, upstream, policy, nil)

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if uses := secretUses(); len(uses) != 0 {
		t.Errorf("secret.use was reported for plain HTTP, which never attaches a credential: %v", uses)
	}
	recorded := waitForAttempt(t, attempts, func(a Attempt) bool { return a.Allowed })
	for _, a := range recorded {
		if a.Mode != ModePlain {
			t.Errorf("mode = %q for genuinely plain HTTP, want %q (this must not move)", a.Mode, ModePlain)
		}
	}
	got := withheld()
	if len(got) == 0 {
		t.Fatal("no secret.withheld was reported for a bound secret reached over plain HTTP")
	}
	if !strings.HasSuffix(got[0], ":"+WithheldUnencrypted) {
		t.Errorf("withheld reason = %q, want it to end in %q (this must not move)", got[0], WithheldUnencrypted)
	}
}

// The case S5d fixes: an absolute-form request naming an https:// target,
// sent straight to the proxy with no CONNECT first. forwardHTTP still
// performs the fetch itself, over a real, certificate-validated TLS
// connection — so the record must not say the connection was plaintext.
func TestAbsoluteFormHTTPSWithoutConnectIsRecordedTruthfully(t *testing.T) {
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "ok")
	}))
	defer upstream.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{atoiOrZero(portStr)}, Secrets: []*Secret{secret}}
	proxyAddr, attempts, secretUses, withheld, _ := proxyFor(t, upstream, policy, nil)

	// forwardHTTP fetches through forwardTransport (F2 gave it one of its own,
	// separate from http.DefaultTransport, so its DialContext could carry the
	// resolved-address check) — so this test's self-signed certificate has to
	// be trusted there instead. Swapped for the length of this test and
	// restored after; nothing else in this package runs concurrently with it.
	prevTransport := forwardTransport
	forwardTransport = upstream.Client().Transport
	defer func() { forwardTransport = prevTransport }()

	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	// Absolute-form, scheme https, no CONNECT anywhere in this exchange.
	fmt.Fprintf(raw, "GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstream.URL, host+":"+portStr)
	resp, err := http.ReadResponse(bufio.NewReader(raw), nil)
	if err != nil {
		t.Fatalf("reading the proxy's response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q, want the upstream's own response, proving the fetch actually happened", body)
	}

	// No credential attached — unchanged by this fix. Injection still lives
	// only on the CONNECT+terminate path.
	if sawAuth != "" {
		t.Errorf("a credential was attached to a request forwardHTTP handled directly: %q", sawAuth)
	}
	if uses := secretUses(); len(uses) != 0 {
		t.Errorf("secret.use was reported for a request that never carried the credential: %v", uses)
	}

	// The fetch really was over TLS: RoundTrip had to verify a certificate
	// against trusted roots to get "ok" back at all. Nothing recorded may
	// claim otherwise.
	recorded := waitForAttempt(t, attempts, func(a Attempt) bool { return a.Allowed })
	for _, a := range recorded {
		if a.Mode == ModePlain {
			t.Errorf("mode = %q for a request served over real TLS; ModePlain's own doc says "+
				`"nothing was encrypted", which is false here: %+v`, a.Mode, a)
		}
	}
	for _, w := range withheld() {
		if strings.HasSuffix(w, ":"+WithheldUnencrypted) {
			t.Errorf("withheld reason %q claims a request served over real TLS was plaintext", w)
		}
	}
}
