package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/egress"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
)

// TestWiringBeforeLiveWindowMatters is the behavioral half of the P6-4
// restore-audit fix; TestSnapshotRestoreWiresAuditBeforeResume in this
// package is the structural half that checks snapshotRestore's own source.
//
// It cannot boot a real guest — that needs KVM and Firecracker, which this
// machine does not have (the honest reason there is no true end-to-end test
// of snapshotRestore's restore window in this repository's `go test` suite:
// besides needing a VM, snapshotRestore itself blocks in a signal-select loop
// until the machine is interrupted or exits, which is the shape of a CLI
// command, not a function `go test` can drive — this repo's own convention
// for proving a full CLI flow end-to-end is the dev/accept-*.sh and
// dev/prove-*.sh scripts, not go test). What it can do, with the real
// egress.Proxy, recorder.Recorder and wireProxyAudit this repository ships —
// no VM involved anywhere — is prove the one thing snapshotRestore's fix
// actually depends on: an attempt made through the proxy while
// wireProxyAudit has not run yet is invisible to the recorder, and an
// attempt made after is not. That is exactly the gap that used to exist
// between sandbox.Restore resuming the guest and snapshotRestore getting
// around to wiring the hooks afterward.
func TestWiringBeforeLiveWindowMatters(t *testing.T) {
	t.Run("wired_before_the_attempt_is_captured", func(t *testing.T) {
		root := t.TempDir()
		proxy, addr, upstream, cleanup := newTestEgressProxy(t)
		defer cleanup()

		rec, err := recorder.Open(root, "s-before")
		if err != nil {
			t.Fatal(err)
		}
		// The fixed order: the hooks are live before anything resembling the
		// guest's live window happens, mirroring wireProxyAudit's call in
		// snapshotRestore sitting before sandbox.Restore.
		wireProxyAudit(proxy, rec, "", nil)

		if err := dialThroughProxy(addr, upstream); err != nil {
			t.Fatalf("egress attempt through the proxy: %v", err)
		}
		// Close waits for the proxy's own handler goroutine to finish —
		// including its call to report(), which calls OnEvent — before this
		// goroutine reads the chain back below. Without that barrier this
		// subtest is racing dialThroughProxy's return (the client has read
		// the response) against the server-side goroutine's own remaining
		// work (byte counts, then report()), and can read the chain before
		// the event lands — flaky in exactly the way the sibling subtest
		// below already guards against with the same call.
		proxy.Close()
		rec.Close()

		if !chainHasEgressAttempt(t, root, "s-before") {
			t.Error("an attempt made after wireProxyAudit ran is missing from the recorder chain — " +
				"wireProxyAudit should have captured it")
		}
	})

	t.Run("wired_after_the_attempt_is_missed", func(t *testing.T) {
		root := t.TempDir()
		proxy, addr, upstream, cleanup := newTestEgressProxy(t)
		defer cleanup()

		// The bug's order: the attempt happens while proxy.OnEvent is still
		// nil, standing in for the guest resuming and reaching out during
		// sandbox.Restore or InstallTrustAnchor, before snapshotRestore used
		// to reach its (former) call to wireProxyAudit. Close waits for the
		// proxy's own handler goroutine to finish — including its call to
		// report(), which reads OnEvent — before this goroutine writes
		// OnEvent below; without that barrier the two race on the same field,
		// which -race rightly calls out even though production code never
		// assigns OnEvent while a request is in flight.
		if err := dialThroughProxy(addr, upstream); err != nil {
			t.Fatalf("egress attempt through the proxy: %v", err)
		}
		proxy.Close()

		rec, err := recorder.Open(root, "s-after")
		if err != nil {
			t.Fatal(err)
		}
		wireProxyAudit(proxy, rec, "", nil)
		rec.Close()

		if chainHasEgressAttempt(t, root, "s-after") {
			t.Fatal("an attempt made before wireProxyAudit ran was somehow captured — this subtest's " +
				"premise is wrong, which means it is not demonstrating what it claims to")
		}
		// This branch passing is not good news about the product — it is
		// this test proving the bug it names would really have been silent.
		// The fix in host/snapshot.go is what keeps this repo out of this
		// branch: wireProxyAudit is called before sandbox.Restore there, not
		// after it.
	})
}

// newTestEgressProxy binds a real egress.Proxy on loopback with a policy that
// allows exactly the httptest server it also creates, and returns the proxy,
// the proxy's own listening port, the upstream's URL, and a cleanup func. No
// VM is involved: the proxy is host-side code that serves whatever dials it,
// and a plain net/http client stands in for the guest that would otherwise be
// the only thing on the other end of the CONNECT.
func newTestEgressProxy(t *testing.T) (proxy *egress.Proxy, port int, upstreamURL string, cleanup func()) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	upstreamHost, upstreamPort, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(upstreamPort)
	if err != nil {
		t.Fatal(err)
	}
	proxy = &egress.Proxy{Policy: egress.Policy{Allow: []string{upstreamHost}, Ports: []int{p}}}
	addr, err := proxy.Listen("127.0.0.1:0")
	if err != nil {
		upstream.Close()
		t.Fatal(err)
	}
	go proxy.Serve()
	return proxy, addr, upstream.URL, func() {
		proxy.Close()
		upstream.Close()
	}
}

// dialThroughProxy performs one real HTTP round trip to upstreamURL through
// the proxy at 127.0.0.1:port, standing in for a guest's own egress attempt.
func dialThroughProxy(port int, upstreamURL string) error {
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstreamURL)
	if resp != nil {
		resp.Body.Close()
	}
	return err
}

func chainHasEgressAttempt(t *testing.T, root, id string) bool {
	t.Helper()
	f, err := os.Open(recorder.Path(root, id))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	events, err := recorder.Read(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Type == recorder.TypeEgressAttempt {
			return true
		}
	}
	return false
}
