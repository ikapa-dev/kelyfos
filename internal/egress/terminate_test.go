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
)

const testToken = "ghp_thisisaverysecrettokenvalue"

// proxyFor starts a proxy in front of an upstream test server, with the given
// policy, and returns its address plus everything it reported.
func proxyFor(t *testing.T, upstream *httptest.Server, policy Policy, ca *CA) (string, func() []Attempt, func() []string) {
	t.Helper()

	var mu sync.Mutex
	var attempts []Attempt
	var secrets []string

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
		}
}

// throughProxy performs an HTTPS GET through the proxy's CONNECT, trusting the
// given roots for the inner TLS session.
func throughProxy(t *testing.T, proxyAddr, target string, roots *x509.CertPool) (*http.Response, error) {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { raw.Close() })

	host, _, _ := net.SplitHostPort(target)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "200") {
		body, _ := io.ReadAll(br)
		return nil, fmt.Errorf("proxy refused: %s%s", strings.TrimSpace(line), body)
	}
	for { // drain the rest of the response headers
		l, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}

	inner := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots})
	if err := inner.Handshake(); err != nil {
		return nil, fmt.Errorf("inner handshake: %w", err)
	}
	fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	return http.ReadResponse(bufio.NewReader(inner), nil)
}

// TestTerminationInjectsTheCredential is the heart of P2-6: the client is never
// given the secret, and the server receives it anyway.
func TestTerminationInjectsTheCredential(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}

	proxyAddr, attempts, secretUses := proxyFor(t, upstream, policy, ca)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	target := strings.TrimPrefix(upstream.URL, "https://")
	resp, err := throughProxy(t, proxyAddr, target, roots)
	if err != nil {
		t.Fatalf("request through the proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if got, want := string(body), "Bearer "+testToken; got != want {
		t.Errorf("the upstream server saw Authorization %q, want %q", got, want)
	}

	// The connection must be recorded as terminated, so a user can tell which
	// traffic the proxy could read.
	var found bool
	for _, a := range attempts() {
		if a.Allowed && a.Mode == ModeTerminated {
			found = true
		}
		if a.Mode == ModeTunnelled {
			t.Errorf("a secret-bound domain must be terminated, not tunnelled: %+v", a)
		}
	}
	if !found {
		t.Errorf("no terminated attempt was recorded: %+v", attempts())
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
	proxyAddr, attempts, _ := proxyFor(t, upstream, policy, nil)

	// No KelyfOS CA anywhere: the client validates the real server certificate,
	// which only works because nothing is in the middle.
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())

	resp, err := throughProxy(t, proxyAddr, strings.TrimPrefix(upstream.URL, "https://"), roots)
	if err != nil {
		t.Fatalf("tunnelled request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello" {
		t.Errorf("tunnelled body = %q", body)
	}
	for _, a := range attempts() {
		if a.Mode == ModeTerminated {
			t.Errorf("a domain with no secret must not be terminated: %+v", a)
		}
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
