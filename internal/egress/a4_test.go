package egress

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The audit of 2026-09-01's A4, end to end, against a local TLS origin: a
// credential-bound origin that echoes the Authorization header inside a
// gzipped body used to hand the guest the credential — the byte-based echo
// suppression saw only compressed bytes. Two behaviours close it, and this
// test drives both.
//
// The scrubbing policy is per host, not per request, so the identity request
// is settled by the proxy before the origin ever answers: an origin that
// honours it answers uncompressed, and the echo is scrubbed as usual. An
// origin that ignores it answers compressed, nothing can match inside the
// encoding, and the fact is recorded (secret.unscrubbable) instead of silent.

// a4Proxy builds the proxy with the unscrubbable hook captured, the way
// proxyFor does for the other hooks.
func a4Proxy(t *testing.T, upstream *httptest.Server, policy Policy, ca *CA) (string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var unscrubbable []string
	p := &Proxy{
		Policy:   policy,
		CA:       ca,
		Upstream: upstream.Client().Transport,
		OnUnscrubbable: func(host, encoding string) {
			mu.Lock()
			defer mu.Unlock()
			unscrubbable = append(unscrubbable, host+"|"+encoding)
		},
	}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go p.Serve()
	t.Cleanup(p.Close)
	return fmt.Sprintf("127.0.0.1:%d", port), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), unscrubbable...)
	}
}

// a4ThroughProxy is throughProxy with the guest's own Accept-Encoding choice,
// which is what curl --compressed sends and what the audit's repro used.
func a4ThroughProxy(t *testing.T, proxyAddr, target, acceptEncoding string, roots *x509.CertPool) (*http.Response, error) {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = raw.Close() })
	host, _, _ := net.SplitHostPort(target)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "200") {
		return nil, fmt.Errorf("proxy refused: %s", strings.TrimSpace(line))
	}
	for {
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
	fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: %s\r\nConnection: close\r\n\r\n",
		host, acceptEncoding)
	resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
	return resp, err
}

func TestACompressedEchoOfTheCredentialIsScrubbedOrRefused(t *testing.T) {
	// An origin that echoes the credential it rejected — the exact shape the
	// audit reproduced with httpbin's /gzip — and honours the encoding the
	// request asked for.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := fmt.Sprintf(`{"echo":{"Authorization":"Bearer %s"}}`, testToken)
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			_, _ = gz.Write([]byte(body))
			_ = gz.Close()
			return
		}
		fmt.Fprint(w, body)
	}))
	defer upstream.Close()
	target := strings.TrimPrefix(upstream.URL, "https://")
	host, _, _ := net.SplitHostPort(target)

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	policy := Policy{Allow: []string{host}, Ports: []int{upstreamPort(t, upstream)}, Secrets: []*Secret{secret}}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	// The compliant origin: the proxy asked for identity, so the response the
	// guest sees is plaintext — and scrubbed. The value never arrives.
	{
		addr, unscrubbable := a4Proxy(t, upstream, policy, ca)
		resp, err := a4ThroughProxy(t, addr, target, "gzip", roots)
		if err != nil {
			t.Fatalf("through the proxy: %v", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(raw), testToken) {
			t.Fatalf("the credential reached the guest: %q", raw)
		}
		if !strings.Contains(string(raw), strings.Repeat("*", len(testToken))) {
			t.Errorf("the echo was not scrubbed: %q", raw)
		}
		if got := unscrubbable(); len(got) != 0 {
			t.Errorf("a compliant origin was reported unscrubbable: %v", got)
		}
	}

	// The defiant origin: it compresses whatever the request asked for. The
	// bytes cannot be matched inside the encoding — and that fact is recorded
	// rather than silent.
	defiant := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(fmt.Sprintf(`{"echo":{"Authorization":"Bearer %s"}}`, testToken)))
		_ = gz.Close()
	}))
	defer defiant.Close()
	dtarget := strings.TrimPrefix(defiant.URL, "https://")
	dhost, _, _ := net.SplitHostPort(dtarget)
	secretD := &Secret{Name: "GITHUB_TOKEN", Domain: dhost, Scheme: "Bearer", value: testToken}
	policyD := Policy{Allow: []string{dhost}, Ports: []int{upstreamPort(t, defiant)}, Secrets: []*Secret{secretD}}
	addrD, unscrubbableD := a4Proxy(t, defiant, policyD, ca)
	raw := a4RawThroughProxy(t, addrD, dtarget, "gzip", roots)
	// Refused, not delivered (H4): the guest gets a 502 that names the encoding
	// and closes the connection, the gzip body never reaches the wire, and the
	// credential is nowhere in what arrived.
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("parsing the refusal from the wire dump: %v (%q)", err, raw)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("the defiant origin's compressed echo was answered %d, want 502", resp.StatusCode)
	}
	if !resp.Close {
		t.Error("the refusal did not close the connection")
	}
	if bytes.Contains(raw, []byte{0x1f, 0x8b}) {
		t.Error("a gzip body reached the guest; it should have been refused, not delivered")
	}
	if bytes.Contains(raw, []byte(testToken)) {
		t.Fatalf("the credential reached the guest in the refusal path: %q", raw)
	}
	if !strings.Contains(string(raw), "gzip") {
		t.Errorf("the refusal does not name the encoding it refused:\n%s", raw)
	}
	if got := unscrubbableD(); len(got) != 1 || !strings.Contains(got[0], "gzip") {
		t.Fatalf("the compressed response was not recorded as unscrubbable: %v", got)
	}
}

// a4RawThroughProxy is a4ThroughProxy that returns the raw bytes the proxy
// wrote back, so a refusal can be inspected on the wire — the status, the
// absence of the gzip body, the absence of the credential.
func a4RawThroughProxy(t *testing.T, proxyAddr, target, acceptEncoding string, roots *x509.CertPool) []byte {
	t.Helper()
	raw, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	host, _, _ := net.SplitHostPort(target)
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no CONNECT answer: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("proxy refused the tunnel: %s", strings.TrimSpace(line))
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(l) == "" {
			break
		}
	}
	inner := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots})
	if err := inner.Handshake(); err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: %s\r\nConnection: close\r\n\r\n",
		host, acceptEncoding)
	_ = inner.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, _ := io.ReadAll(inner)
	return out
}

// The plain-HTTP leg shares the identity request and the refusal: a bound
// credential is never attached to an unencrypted request (D6), but the echo
// suppression policy still applies, so the leg asks the origin for identity and
// refuses a compressed answer rather than deliver a body it cannot read (H4).
func TestA4_ThePlainLegAsksForIdentityAndRefusesACompressedAnswer(t *testing.T) {
	var mu sync.Mutex
	var gotAE string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAE = r.Header.Get("Accept-Encoding")
		mu.Unlock()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(fmt.Sprintf(`{"echo":"Bearer %s"}`, testToken)))
		_ = gz.Close()
	}))
	defer origin.Close()
	target := strings.TrimPrefix(origin.URL, "http://")
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)

	secret := &Secret{Name: "TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	var unscrubbable []string
	p := &Proxy{
		Policy:        Policy{Allow: []string{host}, Ports: []int{port}, Secrets: []*Secret{secret}},
		UpstreamPlain: origin.Client().Transport,
		OnUnscrubbable: func(h, e string) {
			mu.Lock()
			unscrubbable = append(unscrubbable, h+"|"+e)
			mu.Unlock()
		},
	}
	proxyPort, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	raw, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(proxyPort))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	fmt.Fprintf(raw, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n", target, target)
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, _ := io.ReadAll(raw)

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(out)), nil)
	if err != nil {
		t.Fatalf("parsing the plain-leg refusal: %v (%q)", err, out)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("the plain leg answered %d, want 502", resp.StatusCode)
	}
	if bytes.Contains(out, []byte(testToken)) {
		t.Fatalf("the credential reached the guest on the plain leg: %q", out)
	}
	if bytes.Contains(out, []byte{0x1f, 0x8b}) {
		t.Error("a gzip body reached the guest on the plain leg")
	}
	mu.Lock()
	ae, uns := gotAE, append([]string(nil), unscrubbable...)
	mu.Unlock()
	if ae != "identity" {
		t.Errorf("the plain leg did not ask the origin for identity: %q", ae)
	}
	if len(uns) != 1 || !strings.Contains(uns[0], "gzip") {
		t.Errorf("the plain leg's compressed refusal was not recorded: %v", uns)
	}
}
