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
	"sync/atomic"
	"testing"
	"time"
)

// f16BigBody is the size of the response the write-side test asks for.
const f16BigBody = 64 << 20

// f16Tunnel opens a terminated tunnel to a secret-bound host and hands back the
// inside of it: the TLS connection the guest would write its requests on, after
// the CONNECT and the handshake, with nothing sent on it yet.
//
// The secret matters. This is the one path where the proxy decrypts and
// attaches the operator's credential, so it is the one place where holding a
// slot open is worth doing and where anything the proxy buffers is buffered
// while holding a credential.
func f16Tunnel(t *testing.T, tweak ...func(*Proxy)) (*tls.Conn, string, func() int, func() []Attempt) {
	t.Helper()

	var hits atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Drained before answering, which is what an origin that accepts an
		// upload does — and what makes the proxy actually stream a request
		// body rather than abandon it. An origin that replies without reading
		// lets RoundTrip return immediately, so a test written against one
		// never exercises the body path at all and passes on code that has no
		// bound on it whatsoever.
		n, _ := io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/echo-len" {
			fmt.Fprintf(w, "%d", n)
			return
		}
		if r.URL.Path == "/big" {
			// Big enough that no socket buffer, TLS record queue or proxy
			// copy buffer can swallow it, so a guest that stops reading really
			// does block the proxy's write rather than merely slow it.
			_, _ = w.Write(make([]byte, f16BigBody))
			return
		}
		fmt.Fprint(w, "ok")
	}))
	// A deliberately tolerant origin. Go's own http.Server caps request
	// headers at 1 MiB and answers 431 itself, so an ordinary httptest server
	// returns exactly the status this test is looking for — from the wrong
	// end. The proxy would have buffered the whole 4 MiB in host memory first,
	// which is the finding, and the test would have gone green on the unfixed
	// code. Raising the origin's cap is what makes the 431 mean "the proxy
	// refused it" and nothing else.
	upstream.Config.MaxHeaderBytes = 64 << 20
	upstream.StartTLS()
	t.Cleanup(upstream.Close)
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	secret := &Secret{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}
	var amu sync.Mutex
	var attempts []Attempt
	p := &Proxy{
		Policy: Policy{
			Allow:   []string{host},
			Ports:   []int{upstreamPort(t, upstream)},
			Secrets: []*Secret{secret},
		},
		CA:       ca,
		Upstream: upstream.Client().Transport,
		OnEvent: func(a Attempt) {
			amu.Lock()
			defer amu.Unlock()
			attempts = append(attempts, a)
		},
	}
	for _, f := range tweak {
		f(p)
	}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.AnchorPEM()) {
		t.Fatal("the CA anchor is not usable as a trust root")
	}

	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })

	target := strings.TrimPrefix(upstream.URL, "https://")
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT refused: %s", strings.TrimSpace(line))
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
	if n := br.Buffered(); n != 0 {
		t.Fatalf("test bug: %d bytes buffered past the CONNECT reply", n)
	}

	inner := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: roots})
	if err := inner.Handshake(); err != nil {
		t.Fatalf("inner handshake: %v", err)
	}
	t.Cleanup(func() { inner.Close() })
	return inner, host, func() int { return int(hits.Load()) },
		func() []Attempt {
			amu.Lock()
			defer amu.Unlock()
			return append([]Attempt(nil), attempts...)
		}
}

// The finding: handle gives the FIRST request on a raw connection a header
// budget and a deadline, then clears both before calling terminate — and
// terminate parses every subsequent request itself, with http.ReadRequest on a
// plain bufio.Reader. textproto has no header-size cap of its own, so one
// header line of arbitrary length is buffered in host memory in full. Times
// maxConcurrentConnections, that is an out-of-memory the guest can trigger at
// will, on the one connection kind that is holding a credential while it does.
func TestF16_AnOversizedHeaderInsideTheTunnelIsRefused(t *testing.T) {
	inner, host, upstreamHits, recorded := f16Tunnel(t)

	// Four mebibytes in one header value, properly terminated: the request is
	// well-formed, so nothing but a budget stops it being buffered whole.
	//
	// Written from a goroutine because a proxy that refuses this correctly
	// answers while the guest is still sending — 4 MiB does not fit in a
	// socket buffer — so a test that wrote it all before reading would block
	// against a peer that has already stopped listening. A real client hits
	// the same thing; the write error is expected and is not the assertion.
	huge := strings.Repeat("A", 4<<20)
	written := make(chan error, 1)
	go func() {
		_, err := fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nX-Pad: %s\r\n\r\n", host, huge)
		written <- err
	}()

	if err := inner.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
	if err != nil {
		t.Fatalf("no answer to the oversized request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431: a %d-byte header line was accepted and buffered "+
			"inside the terminated tunnel, which is the whole finding", resp.StatusCode, len(huge))
	}
	// And the 431 has to be the proxy's. The origin never seeing the request
	// is what says the bytes were refused rather than relayed.
	select {
	case <-written:
	case <-time.After(30 * time.Second):
		t.Fatal("the write never finished or failed")
	}
	if n := upstreamHits(); n != 0 {
		t.Errorf("the origin was reached %d times, so the oversized request was buffered whole "+
			"and forwarded; the refusal has to happen before that", n)
	}

	// The refusal has its own reason. bad_request would say the proxy could
	// not parse this request; what happened is that it refused to, and an
	// operator reading the chain wants to tell a broken client from one
	// sending four mebibytes of headers.
	// Waited on the SUMMARY, not on the refusal, and this is the whole
	// difference between an assertion and a decoration. The refusal is reported
	// strictly first — report(header_too_large), writeStatus, drain, break,
	// report(summary) — so waiting for the refusal returns a slice that usually
	// does not contain the summary yet, and `if summary != nil && …` then
	// asserts nothing at all. Demonstrated: make the drain take its full two
	// seconds and mutate Mode, and the guarded version passes. It fires today
	// only because a 4 MiB burst fills the 1 MiB drain instantly.
	var refusal, summary *Attempt
	for _, a := range waitForAttempt(t, recorded, func(a Attempt) bool {
		return a.Allowed && a.Mode != ""
	}) {
		cp := a
		switch {
		case a.Reason == ReasonHeaderTooLarge:
			refusal = &cp
		case a.Allowed:
			summary = &cp
		}
	}
	if refusal == nil {
		t.Fatal("the 431 was not recorded")
	}
	if summary == nil {
		t.Fatal("the connection summary was not recorded, so the half of this test that pins " +
			"the two-event decision checked nothing")
	}
	if refusal.Reason != ReasonHeaderTooLarge {
		t.Errorf("reason = %q, want %q", refusal.Reason, ReasonHeaderTooLarge)
	}
	if refusal.Allowed {
		t.Errorf("the refusal is recorded as allowed: %+v", refusal)
	}
	// And the connection summary still says allowed, mode=terminated — which
	// is correct and is pinned here so it is not "fixed" later. It describes
	// the CONNECTION: policy did permit this host and port, and the proxy did
	// decrypt it. A connection that carried three good requests before the
	// fourth was refused would be described worse by allowed=false, and would
	// lose the byte counts that make the receipt worth having.
	if summary.Mode != ModeTerminated {
		t.Errorf("the connection summary says mode=%q, want %q", summary.Mode, ModeTerminated)
	}
	if !summary.Allowed {
		t.Errorf("the connection summary says allowed=false; it describes the connection, which "+
			"policy permitted and the proxy decrypted: %+v", summary)
	}
}

// The slow half of the same finding, and the one that costs a slot rather than
// memory: a request that starts and never finishes. Before this, terminate had
// no read deadline at all once handle cleared it, so a guest could open a
// terminated tunnel, send half a header, and hold one of the 128 connection
// slots — with a credential bound to it — indefinitely.
//
// The half-sent request is the SECOND one on this tunnel, deliberately. On the
// first, the wait for the request to begin is already armed with
// readHeaderTimeout, so deleting the header deadline that follows it leaves
// that first arm doing the job and a test written against request zero stays
// green with the mechanism removed. From the second request on, the wait is
// armed with terminatedIdleTimeout — two minutes — and only the header
// deadline bounds a header that starts and stops.
func TestF16_AHalfSentHeaderInsideTheTunnelDoesNotHoldTheSlot(t *testing.T) {
	inner, host, _, _ := f16Tunnel(t)

	// One complete request first, so what follows is measured against the gap
	// bound rather than the first-request bound.
	if _, err := fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatalf("writing the first request: %v", err)
	}
	if err := inner.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(inner)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the first request got no answer: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Now a request line and one header, and then nothing: never the blank
	// line that ends the block.
	if _, err := fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\n", host); err != nil {
		t.Fatalf("writing the partial request: %v", err)
	}

	// Generous against readHeaderTimeout, and far under terminatedIdleTimeout,
	// so a pass means the header deadline fired and not the gap bound.
	deadline := readHeaderTimeout + 20*time.Second
	if deadline >= terminatedIdleTimeout {
		t.Fatalf("test bug: %v would not distinguish the header deadline from the gap bound (%v)",
			deadline, terminatedIdleTimeout)
	}
	if err := inner.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = br.Read(make([]byte, 1))
	if err == nil {
		return // the proxy answered and is closing; either way it did not park
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("after %v the proxy was still holding a half-sent second request open inside a "+
			"terminated tunnel; the header deadline is %v and the gap bound is %v",
			time.Since(start), readHeaderTimeout, terminatedIdleTimeout)
	}
}

// Keep-alive still works, and the budget is per request rather than per
// connection: a second request on the same tunnel must not be refused because
// the first one spent bytes.
func TestF16_KeepAliveSurvivesThePerRequestBudget(t *testing.T) {
	inner, host, _, _ := f16Tunnel(t)
	for i := 0; i < 3; i++ {
		// 400 KiB each time: legal alone against the 1 MiB budget, and 1.2 MiB
		// across the three, so a budget carried across requests instead of
		// reset for each one runs out on the third. At 64 KiB it never did,
		// and this test's own failure message named the thing it could not
		// detect — removing the reset left the whole suite green.
		pad := strings.Repeat("B", 400<<10)
		if _, err := fmt.Fprintf(inner, "GET / HTTP/1.1\r\nHost: %s\r\nX-Pad: %s\r\n\r\n", host, pad); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if err := inner.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
		if err != nil {
			t.Fatalf("request %d got no answer: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 — the header budget is being carried "+
				"across requests instead of reset for each", i, resp.StatusCode)
		}
	}
}

// The slow variant, which the first pass at F16 did not close: the header
// bounds were applied and then cleared before the body, and nothing re-armed
// them. A guest CONNECTs to a secret-bound host, sends a request declaring a
// megabyte of body, and then dribbles — the finding's own words are "a byte a
// minute". http.ReadRequest returns, the deadline is cleared, and RoundTrip
// streams the body from the same reader with no clock on it at all: the tunnel
// stays open, decrypted, holding the operator's credential and one of the 128
// slots, for as long as the guest keeps trickling.
//
// The bound is a rolling one, re-armed as bytes actually arrive, so it stops a
// stall without stopping a transfer — the same distinction the header and gap
// bounds already make.
func TestF16_ADribbledBodyDoesNotHoldTheSlot(t *testing.T) {
	inner, host, _, _ := f16Tunnel(t)

	const declared = 1 << 20
	if _, err := fmt.Fprintf(inner,
		"POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", host, declared); err != nil {
		t.Fatalf("writing the request head: %v", err)
	}

	// Closure is observed by reading: a proxy that gave up closes the tunnel,
	// and the write side can absorb a byte into a socket buffer long after
	// that.
	closed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, inner)
		close(closed)
	}()

	// Slower than the stall bound and no faster than the finding's "byte a
	// minute". Stopped by the test finishing, whichever way it goes.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := inner.Write([]byte("x")); err != nil {
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(bodyStallTimeout + 5*time.Second):
			}
		}
	}()

	give := 3*bodyStallTimeout + 20*time.Second
	start := time.Now()
	select {
	case <-closed:
		t.Logf("the tunnel closed after %v, against a %v stall bound",
			time.Since(start).Round(time.Second), bodyStallTimeout)
	case <-time.After(give):
		t.Fatalf("after %v the proxy was still streaming a dribbled body inside a terminated "+
			"tunnel — one of %d slots and a decrypted credential, held for the price of a byte "+
			"every %v", give, maxConcurrentConnections, bodyStallTimeout+5*time.Second)
	}
}

// The other half of the same finding, and the one a rolling stall bound cannot
// reach on its own: a guest that dribbles just fast enough to keep re-arming
// it. Occupancy has to be bounded too, and the first pass bounded only silence
// — idleSpent charged the wait between requests and nothing else, so 4096
// requests each spending 9.9s inside the header deadline came to over eleven
// hours of held slot while the ten-minute idle budget barely moved.
//
// Measured, because the first version of this test divided two constants and
// asserted the quotient — and deleting the one line that charges the header
// read, which is the whole mechanism, left it green. A test that cannot fail
// when the mechanism is removed is not testing the mechanism.
//
// Eight requests, each header dribbled over a second and a half, down one
// tunnel with a five-second budget. Charging the header read, that budget is
// gone after three or four of them; not charging it, all eight are served
// because the gaps between them are instant.
func TestF16_TheIdleBudgetChargesTimeSpentReadingHeaders(t *testing.T) {
	const budget = 5 * time.Second
	inner, host, _, _ := f16Tunnel(t, func(p *Proxy) { p.terminatedIdleBudget = budget })

	const want = 8
	served := 0
	for i := 0; i < want; i++ {
		// A second and a half per header, in three parts, all of it well
		// inside readHeaderTimeout — this is a slow client, not a stalled one,
		// and nothing else in the loop should object to it.
		parts := []string{
			"GET / HTTP/1.1\r\n",
			"Host: " + host + "\r\n",
			"\r\n",
		}
		failed := false
		for _, part := range parts {
			if _, err := io.WriteString(inner, part); err != nil {
				failed = true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if failed {
			break
		}
		if err := inner.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
		if err != nil {
			break
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			break
		}
		served++
	}

	if served == 0 {
		t.Fatal("no request was served at all, so this measures nothing about the budget")
	}
	if served >= want {
		t.Fatalf("all %d requests were served on a %v idle budget with %v of header reading each: "+
			"the time spent reading a request header is not being charged, which is the line that "+
			"closes the eleven-hour arithmetic", want, budget, 1500*time.Millisecond)
	}
	t.Logf("%d of %d requests served before the %v idle budget ran out", served, want, budget)
}

// The bounds exist and are ordered sensibly. Arithmetic, and labelled as such:
// the companion to the measurements above, not a substitute for any of them.
//
// The ordering assertion is the one worth keeping. A per-request deadline short
// enough to stop a slow header is far too short to be the gap between two real
// requests on a keep-alive connection, and applying one bound to both is the
// mistake the review's own snippet makes.
func TestF16_TheTerminatedBoundsAreOrderedSensibly(t *testing.T) {
	if maxTerminatedConnTime <= 0 {
		t.Error("a terminated connection has no ceiling on its own lifetime")
	}
	if bodyStallTimeout <= 0 {
		t.Error("a request body may stall forever")
	}
	if maxTerminatedIdleTotal <= 0 {
		t.Error("a terminated connection may sit idle forever")
	}
	if maxRequestsPerTerminatedConn <= 0 {
		t.Error("a terminated connection may serve unlimited requests")
	}
	if terminatedIdleTimeout <= readHeaderTimeout {
		t.Errorf("the gap allowed between two requests (%v) is no longer than the deadline for "+
			"finishing one header (%v); keep-alive clients that think between calls would be "+
			"disconnected", terminatedIdleTimeout, readHeaderTimeout)
	}
	if maxTerminatedIdleTotal < terminatedIdleTimeout {
		t.Errorf("the total idle budget (%v) is smaller than one permitted gap (%v)",
			maxTerminatedIdleTotal, terminatedIdleTimeout)
	}
	if maxTerminatedIdleTotal > maxTerminatedConnTime {
		t.Errorf("the idle budget (%v) is larger than the whole connection's ceiling (%v), so it "+
			"can never be reached", maxTerminatedIdleTotal, maxTerminatedConnTime)
	}
}

// The header budget is released before the body, and this is the test that says
// so. Every comment on this leg claims it — "the body is not a header and must
// not be charged to a header's budget" — and until now nothing checked it: the
// oversized test sends no body, the dribbled one sends a handful of bytes, and
// the keep-alive one sends none. Deleting the single line that releases the
// limiter would have silently truncated every request body over a megabyte,
// with the origin seeing a short read and nobody seeing why.
func TestF16_ARequestBodyIsNotChargedToTheHeaderBudget(t *testing.T) {
	inner, host, _, _ := f16Tunnel(t)

	const body = 3 << 20 // comfortably over maxRequestHeaderBytes
	if _, err := fmt.Fprintf(inner,
		"POST /echo-len HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", host, body); err != nil {
		t.Fatalf("writing the request head: %v", err)
	}
	go func() { _, _ = inner.Write(make([]byte, body)) }()

	if err := inner.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(inner), nil)
	if err != nil {
		t.Fatalf("no answer to the %d-byte body: %v", body, err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200: a body the size of a real upload was refused as though "+
			"it were a header", resp.StatusCode)
	}
	if want := fmt.Sprint(body); string(got) != want {
		t.Fatalf("the origin received %s bytes of a %s-byte body — the header budget is being "+
			"charged for the body and truncating it", got, want)
	}
}

// The write side, which had no clock at all until it was measured. Every
// deadline in this package was a read deadline, so a guest that asked a
// secret-bound origin for a large body and then stopped reading blocked the
// proxy inside resp.Write once its receive window filled — and the connection
// ceiling never reached it, because the ceiling is consulted at the top of the
// loop and in the clamp, neither of which runs while a write is blocked.
//
// Worse than one held slot: Serve takes its semaphore before Accept, so 128 of
// these stop the proxy accepting anything, and Close waits on the WaitGroup, so
// teardown blocks with them.
//
// The guest here never reads until the bound has had time to fire. Reading
// earlier would unblock the proxy and let it finish, which is exactly what the
// attack does not do — so the assertion is on how much arrived, not on how long
// it took.
func TestF16_AGuestThatStopsReadingDoesNotHoldTheWriteSide(t *testing.T) {
	inner, host, _, _ := f16Tunnel(t)

	if _, err := fmt.Fprintf(inner, "GET /big HTTP/1.1\r\nHost: %s\r\n\r\n", host); err != nil {
		t.Fatalf("writing the request: %v", err)
	}

	// Not a byte read while the clock runs out.
	time.Sleep(bodyStallTimeout + 5*time.Second)

	// Now drain whatever is there. A proxy that gave up has closed, so this
	// ends at whatever the kernel and the TLS layer had already buffered; one
	// that is still waiting on the guest resumes here and delivers the lot.
	if err := inner.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := io.Copy(io.Discard, inner)
	if got >= f16BigBody {
		t.Fatalf("the whole %d-byte body arrived after the guest ignored it for %v: the proxy was "+
			"still holding the write open, which is one of %d slots — and Serve takes its "+
			"semaphore before Accept, so enough of these stop it accepting at all (err %v)",
			f16BigBody, bodyStallTimeout+5*time.Second, maxConcurrentConnections, err)
	}
	t.Logf("the proxy gave up after delivering %d of %d bytes to a guest that stopped reading",
		got, f16BigBody)
}

// The ceiling has to reach a guest that never leaves one request, and nothing
// exercised it: removing the clamp in at() left this whole suite green.
//
// It is the only bound that reaches this guest. The rolling stall bound cannot
// — a byte every half second is not stalling by any per-read definition, and no
// per-read rule will ever say otherwise. The top-of-loop ceiling check cannot
// either, because a request whose body never ends never gets back to the top of
// the loop, which is exactly what the write-side comment in terminate.go says
// about its own case. That leaves the clamp, and the clamp was untested — the
// same "two divided constants" failure the idle budget already had, one level
// up, on the bound docs/networking.md describes as load-bearing.
func TestF16_TheConnectionCeilingReachesAGuestInsideOneRequest(t *testing.T) {
	const ceiling = 5 * time.Second
	inner, host, _, _ := f16Tunnel(t, func(p *Proxy) { p.terminatedConnCeiling = ceiling })

	const declared = 1 << 20
	if _, err := fmt.Fprintf(inner,
		"POST /echo-len HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", host, declared); err != nil {
		t.Fatalf("writing the request head: %v", err)
	}

	closed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, inner)
		close(closed)
	}()

	// Twenty times a second faster than the stall bound, so the rolling clock
	// is re-armed on every read and never fires. Only the ceiling is left.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := inner.Write([]byte("x")); err != nil {
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()

	give := ceiling + 20*time.Second
	start := time.Now()
	select {
	case <-closed:
		t.Logf("the tunnel closed after %v, against a %v ceiling",
			time.Since(start).Round(time.Second), ceiling)
	case <-time.After(give):
		t.Fatalf("after %v the proxy was still reading a body dribbled every 500ms — faster than "+
			"the %v stall bound, so the rolling clock never fires — past the %v ceiling. The clamp "+
			"in at() is the only thing that reaches a guest which never leaves one request",
			give, bodyStallTimeout, ceiling)
	}
}

// The inner TLS handshake, which had no clock in either direction. handle
// clears its deadline before calling terminate, and the bodyClock does not
// exist until the handshake has returned — so between those two points a guest
// that answered the CONNECT and then sent five bytes of a truncated TLS record
// header sat inside Handshake for as long as it liked. Measured at 45 seconds.
//
// Pre-existing rather than introduced by F16, but docs/networking.md now opens
// with "a terminated connection is bounded", which was true of everything after
// the handshake and not of the handshake itself.
func TestF16_AStalledInnerHandshakeDoesNotHoldTheSlot(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))

	ca, err := NewCA()
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxy{
		Policy: Policy{
			Allow:   []string{host},
			Ports:   []int{upstreamPort(t, upstream)},
			Secrets: []*Secret{{Name: "GITHUB_TOKEN", Domain: host, Scheme: "Bearer", value: testToken}},
		},
		CA:       ca,
		Upstream: upstream.Client().Transport,
	}
	port, err := p.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve()
	t.Cleanup(p.Close)

	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	target := strings.TrimPrefix(upstream.URL, "https://")
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(raw)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT refused: %s", strings.TrimSpace(line))
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

	// A TLS record header announcing 512 bytes of handshake, and then nothing.
	// The proxy is now inside tls.Conn.Handshake waiting for a body that will
	// never arrive.
	if _, err := raw.Write([]byte{0x16, 0x03, 0x01, 0x02, 0x00}); err != nil {
		t.Fatalf("writing the truncated record: %v", err)
	}

	deadline := readHeaderTimeout + 20*time.Second
	if err := raw.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = br.Read(make([]byte, 1))
	if err == nil {
		return // the proxy said something and is closing; either way it gave up
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("after %v the proxy was still inside the inner TLS handshake, holding one of %d "+
			"slots — and Serve takes its semaphore before Accept, so enough of these stop it "+
			"accepting at all. The handshake bound is %v", time.Since(start),
			maxConcurrentConnections, readHeaderTimeout)
	}
}
