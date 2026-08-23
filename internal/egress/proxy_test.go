package egress

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
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
	var got []Attempt
	p := &Proxy{Policy: Policy{Allow: []string{host}, Ports: []int{atoiOrZero(port)}}}
	p.OnEvent = func(a Attempt) { got = append(got, a) }
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

	if len(got) != 1 {
		t.Fatalf("want one attempt, got %d: %+v", len(got), got)
	}
	a := got[0]
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
