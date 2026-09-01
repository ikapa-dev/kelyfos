package egress

import (
	"crypto/tls"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The finding: newForwardTransport cloned http.DefaultTransport, and
// DefaultTransport carries Proxy: ProxyFromEnvironment. On any host with
// HTTPS_PROXY or HTTP_PROXY set — every corporate laptop — the plain-HTTP and
// direct-TLS paths dial that proxy instead of the origin, and the upstream
// proxy is then what resolves the name. dialContextSafe is still installed and
// still runs, but it is handed the corporate proxy's address, so the
// resolved-address check never sees where the allowlisted name actually points:
// F14's table is routed around on exactly the two paths it was just widened
// for. The CONNECT tunnel and the terminated leg dial directly, so the
// behaviour differed silently by path.
func TestF15_TheForwardTransportChainsToNoProxy(t *testing.T) {
	if p := newForwardTransport().Proxy; p != nil {
		t.Error("the forward transport has a Proxy function, so a host with HTTPS_PROXY set " +
			"sends the sandbox's traffic to that proxy and the resolved-address check never " +
			"sees the real destination. The egress proxy is the proxy; it must not chain to " +
			"one it did not configure.")
	}
}

// The same thing with the environment genuinely in force, which needs a fresh
// process: net/http caches the proxy environment behind a sync.Once the first
// time ProxyFromEnvironment is called, so t.Setenv in this package has no
// effect once any earlier test has touched a transport — the review's own
// prescribed test would have passed on the unfixed code. Measured, not assumed;
// see the report for this task.
func TestF15_TheForwardTransportIgnoresTheHostsProxyEnvironment(t *testing.T) {
	if os.Getenv("KELYFOS_F15_CHILD") == "1" {
		req, err := http.NewRequest("GET", "https://api.example.com/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		// Prove the child really is running with the environment set, so a
		// green result cannot mean "nothing was configured to go wrong".
		if u, err := http.ProxyFromEnvironment(req); err != nil || u == nil {
			t.Fatalf("this child was meant to run with HTTPS_PROXY set and did not: (%v, %v)", u, err)
		}
		tr := newForwardTransport()
		if tr.Proxy == nil {
			return
		}
		u, err := tr.Proxy(req)
		if err != nil {
			t.Fatalf("the transport's Proxy returned an error: %v", err)
		}
		if u != nil {
			t.Fatalf("with HTTPS_PROXY set, the forward transport would send this request to %s "+
				"instead of to the origin — and the resolved-address check would be asked about "+
				"%s rather than about where api.example.com resolves", u, u.Host)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(),
		"KELYFOS_F15_CHILD=1",
		"HTTPS_PROXY=http://127.0.0.1:1",
		"HTTP_PROXY=http://127.0.0.1:1",
		"https_proxy=http://127.0.0.1:1",
		"http_proxy=http://127.0.0.1:1",
	)
	out, err := cmd.CombinedOutput()
	// The child's exit status alone would report a build failure, a panic or
	// an unrelated t.Fatal as this finding. Read what it actually said.
	const sentinel = "with HTTPS_PROXY set, the forward transport would send this request to"
	switch {
	case err != nil && strings.Contains(string(out), sentinel):
		t.Fatalf("the forward transport honoured the host's proxy environment:\n%s", out)
	case err != nil:
		t.Fatalf("the child failed for some other reason, so this test proves nothing: %v\n%s", err, out)
	case !strings.Contains(string(out), "PASS: "+t.Name()):
		t.Fatalf("the child exited 0 without running %s; nothing was checked:\n%s", t.Name(), out)
	}
}

// Both egress transports are built field by field from a zero value, so the
// next thing Go adds to DefaultTransport does not arrive uninvited either.
//
// A clone is not a smaller version of this: it is this plus whatever the
// standard library decides later, and Proxy is the field that already went
// wrong that way. The cost of building explicitly is that everything the clone
// used to supply has to be supplied on purpose — DefaultTransport's
// MaxIdleConns 100, IdleConnTimeout 90s and TLSHandshakeTimeout 10s are all
// zero on a zero value, and zero means "no limit" for each. Dropping them
// silently would trade a proxy leak for unbounded idle connections and a TLS
// handshake that can hang forever, so they are asserted here rather than left
// to inspection.
//
// ExpectContinueTimeout is asserted for a different reason and the difference
// matters: zero there means no wait at all — Go sends the body immediately
// without waiting for a 100-continue — not an unbounded one. One second is the
// value we want; it is not a hole being closed.
//
// ResponseHeaderTimeout is in neither transport's ancestry: DefaultTransport
// leaves it zero too, so "everything the clone supplied" never named it. An
// origin that accepts, completes TLS and then says nothing holds a goroutine,
// a socket and — on the terminated leg — the credential, indefinitely.
func TestF15_BothEgressTransportsSetTheirOwnFields(t *testing.T) {
	for _, c := range []struct {
		name string
		tr   *http.Transport
	}{
		{"forward", newForwardTransport()},
		{"terminated", newTerminatedTransport()},
	} {
		tr := c.tr
		if tr.Proxy != nil {
			t.Errorf("%s: Proxy must be nil — this proxy never chains to another (F15)", c.name)
		}
		if tr.DialContext == nil {
			t.Errorf("%s: DialContext must be dialContextSafe, or the resolved-address check "+
				"does not run on this path (F2, F14)", c.name)
		}
		if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("%s: TLSClientConfig.MinVersion must be TLS 1.2", c.name)
		}
		if tr.ForceAttemptHTTP2 {
			t.Errorf("%s: ForceAttemptHTTP2 must be false", c.name)
		}
		// Zero means unbounded for the first three. That is the trap in
		// building from a zero value, and the reason each is named.
		if tr.MaxIdleConns == 0 {
			t.Errorf("%s: MaxIdleConns is 0, which means unlimited idle connections", c.name)
		}
		if tr.IdleConnTimeout == 0 {
			t.Errorf("%s: IdleConnTimeout is 0, so an idle connection is never reaped", c.name)
		}
		if tr.TLSHandshakeTimeout == 0 {
			t.Errorf("%s: TLSHandshakeTimeout is 0, so a stalled handshake holds a goroutine "+
				"and a socket forever", c.name)
		}
		if tr.ExpectContinueTimeout == 0 {
			t.Errorf("%s: ExpectContinueTimeout is 0, which makes Go send the body immediately "+
				"without waiting for a 100-continue. Not a hang — but not what this proxy "+
				"chose either", c.name)
		}
		if tr.ResponseHeaderTimeout == 0 {
			t.Errorf("%s: ResponseHeaderTimeout is 0, so an origin that accepts, completes TLS "+
				"and then says nothing holds a goroutine, a socket and the credential forever", c.name)
		}
	}
}

// The upstream dial has a bound of its own. dialContextSafe built its dialer
// with dialerFor(host, 0) — no timeout — and neither transport supplies one,
// so before this an upstream that accepted nothing held the connection until
// the OS gave up, which on Linux is over two minutes.
func TestF15_TheUpstreamDialIsBounded(t *testing.T) {
	if upstreamDialTimeout <= 0 {
		t.Fatal("the upstream dial has no timeout")
	}
	if upstreamDialTimeout > 30*time.Second {
		t.Errorf("upstreamDialTimeout is %v, which is longer than any dial this proxy should wait on",
			upstreamDialTimeout)
	}
}
