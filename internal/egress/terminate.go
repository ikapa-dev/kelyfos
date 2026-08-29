package egress

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// bodyClock owns the read deadline on a terminated connection.
//
// Two modes, because reading a request body and waiting for one are different
// problems. Off, the caller arms an absolute deadline itself — for the gap
// between requests, and for the header block once bytes start arriving. On, the
// deadline is re-armed before every read, so a body that keeps delivering keeps
// its clock and a body that stops does not.
//
// hard is the connection's own ceiling and is never exceeded by either mode:
// once it passes, every read fails immediately, whatever the guest is doing.
//
// rolling is atomic because net/http's transport streams a request body from
// its own goroutine while this one is in RoundTrip — the same reason `sent` a
// few lines down is atomic.
type bodyClock struct {
	c       net.Conn
	stall   time.Duration
	hard    time.Time
	rolling atomic.Bool
}

func (b *bodyClock) Read(p []byte) (int, error) {
	if b.rolling.Load() {
		b.arm(b.stall)
	}
	return b.c.Read(p)
}

// Write is the other half, and it was missing. Every deadline in this package
// was a read deadline, so a guest that asked a secret-bound origin for a large
// body and then simply stopped reading blocked the proxy inside resp.Write once
// its receive window filled — with no clock on it at all. Measured with the
// connection ceiling shrunk to twelve seconds: still open and still delivering
// twenty-seven seconds past it, because the ceiling is only consulted at the
// top of the loop and in arm's clamp, and neither is reached while a write is
// blocked.
//
// The cost is worse than one held slot. Serve takes its semaphore BEFORE
// Accept, so 128 of these stop the proxy accepting anything at all, and
// Close waits on the WaitGroup, so teardown blocks with them. That is this
// finding's own scenario moved from the read side to the write side.
//
// Unconditional rather than gated on rolling: a write to the guest only
// happens when the proxy has something to deliver, and delivery that is
// getting nowhere is a stall whenever it happens.
func (b *bodyClock) Write(p []byte) (int, error) {
	b.armWrite(b.stall)
	return b.c.Write(p)
}

// arm and armWrite set one direction each, never past the connection's ceiling.
// Deliberately not SetDeadline: a guest that has stopped sending its request
// body but is still draining the response is making progress in one direction
// only, and a single shared deadline would let either direction excuse the
// other.
func (b *bodyClock) arm(d time.Duration)      { _ = b.c.SetReadDeadline(b.at(d)) }
func (b *bodyClock) armWrite(d time.Duration) { _ = b.c.SetWriteDeadline(b.at(d)) }

func (b *bodyClock) at(d time.Duration) time.Time { return notAfter(time.Now().Add(d), b.hard) }

// notAfter is the ceiling clamp, and it is the only thing that reaches a guest
// which never leaves a single request.
//
// The top-of-loop check on the ceiling runs between requests, so a body that
// never ends never gets back to it — and a guest dribbling FASTER than
// bodyStallTimeout re-arms the rolling clock forever without ever stalling by
// that definition. Every deadline this file sets goes through here, so the
// ceiling is what those arms cannot outrun.
//
// A free function rather than a method: the ceiling has to bound the inner TLS
// handshake too, which happens before there is a bodyClock to hang it on.
func notAfter(t, ceiling time.Time) time.Time {
	if t.After(ceiling) {
		return ceiling
	}
	return t
}

// terminate handles a CONNECT to a domain that has a secret bound to it.
//
// This is the one case where the proxy decrypts. It presents a certificate
// minted by the per-run CA, reads the guest's requests, attaches the credential,
// and forwards them over a properly validated TLS connection to the real server.
// The guest never holds the secret, and the proxy never holds it for a domain
// nobody bound one to.
//
// Everything about it is recorded as mode=terminated, so a user can always tell
// which traffic the proxy was able to read (decision D6).
func (p *Proxy) terminate(client net.Conn, host string, port int, bound []*Secret) {
	if p.CA == nil {
		p.report(Attempt{Host: host, Port: port, Reason: ReasonBadRequest})
		writeStatus(client, http.StatusInternalServerError, "kelyfos: no CA for TLS termination")
		return
	}
	leaf, err := p.CA.leafFor(host)
	if err != nil {
		p.report(Attempt{Host: host, Port: port, Reason: ReasonBadRequest})
		writeStatus(client, http.StatusInternalServerError, "kelyfos: "+err.Error())
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	// The ceiling starts here, before the handshake, not after it.
	connTime := maxTerminatedConnTime
	if p.terminatedConnCeiling > 0 {
		connTime = p.terminatedConnCeiling
	}
	hard := time.Now().Add(connTime)

	inner := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	// Between handle clearing its deadline and the bodyClock below existing,
	// there was no clock at all — so a guest that answered the CONNECT and then
	// sent five bytes of a truncated TLS record header sat inside Handshake
	// until it chose to disconnect. Measured at 45 seconds and still going.
	// That is this finding's own scenario one step earlier, with the same cost:
	// Serve takes its semaphore before Accept, so 128 of these stop the proxy
	// accepting anything, and Close waits on the WaitGroup, so teardown blocks
	// with them.
	//
	// SetDeadline rather than SetReadDeadline: a handshake writes as well as
	// reads, and a peer that stops reading mid-handshake blocks it just as
	// surely as one that stops sending. The pair-of-directions argument that
	// applies to the bodyClock does not apply here — there is no per-read
	// re-arming to let one direction excuse the other, only this one absolute
	// bound across the whole exchange.
	_ = client.SetDeadline(notAfter(time.Now().Add(readHeaderTimeout), hard))
	if err := inner.Handshake(); err != nil {
		// Almost always a client that pins certificates, which termination
		// breaks by design. Say so rather than leaving a bare TLS error.
		p.report(Attempt{Host: host, Port: port, Reason: ReasonPinned})
		return
	}
	defer inner.Close()
	// The handshake's deadline is superseded below: the clock arms the read
	// side before every read and the write side before every write, and every
	// read and write from here on goes through it.

	upstreamAddr := net.JoinHostPort(host, strconv.Itoa(port))
	// The same budget the first request on a raw connection gets, applied to
	// every request on this leg. handle sets it, and then clears it before
	// calling us — so from here down there was no ceiling on a header block at
	// all, and http.ReadRequest has none of its own: measured, a 16 MiB header
	// line parses into memory without complaint. One guest, one arbitrarily
	// long header line, times maxConcurrentConnections, on the one connection
	// kind that is holding a credential while it buffers (F16).
	clock := &bodyClock{c: inner, stall: bodyStallTimeout, hard: hard}
	lim := &headerLimitReader{r: clock}
	br := bufio.NewReader(lim)
	var in, out int64
	// Cumulative time this connection has spent not carrying traffic: the gaps
	// between requests and the reading of the request headers themselves.
	var idleSpent time.Duration
	idleBudget := maxTerminatedIdleTotal
	if p.terminatedIdleBudget > 0 {
		idleBudget = p.terminatedIdleBudget
	}

	// A single TLS connection carries many requests when keep-alive is in play,
	// and each one needs the credential.
	for requests := 0; ; requests++ {
		if requests >= maxRequestsPerTerminatedConn {
			break
		}
		if !time.Now().Before(clock.hard) {
			break // this connection has existed for long enough
		}
		// Waiting for the next request to start is a different thing from
		// reading one, and giving them the same deadline is the mistake that
		// is easy to make here. readHeaderTimeout is ten seconds because a
		// request is already assembled in memory before it is sent; the gap
		// between two requests on a keep-alive connection is a client
		// thinking, and ten seconds would disconnect every legitimate one. So
		// the gap gets its own, longer bound, and the header gets the short
		// one — with the clock starting when the first byte actually arrives,
		// which is what Peek is for. The first request on this tunnel is not a
		// gap: the guest has just completed a CONNECT and a handshake to send
		// it, so it gets the short bound too.
		wait := terminatedIdleTimeout
		if requests == 0 {
			wait = readHeaderTimeout
		}
		if left := idleBudget - idleSpent; left < wait {
			wait = left
		}
		if wait <= 0 {
			break // the connection has done nothing but wait for long enough
		}
		clock.rolling.Store(false)
		clock.arm(wait)
		waitStart := time.Now()
		if _, err := br.Peek(1); err != nil {
			break
		}
		idleSpent += time.Since(waitStart)

		// Bytes are arriving; the header block must now finish promptly and
		// within budget. Both are reset per request, so a long first request
		// does not shrink the second — and released again below, because the
		// body is not a header and must not be charged to a header's budget.
		clock.arm(readHeaderTimeout)
		lim.n, lim.limited, lim.hitLimit = maxRequestHeaderBytes, true, false
		headStart := time.Now()

		var attached *Secret
		// sent says the credential reached the socket. Written on the
		// transport's write goroutine and read on this one — a response can
		// come back before a request body has finished being written — so it
		// is atomic rather than a plain flag.
		var sent atomic.Bool
		req, err := http.ReadRequest(br)
		overBudget := lim.hitLimit
		// Released before anything reads a body: whatever the request carries
		// is a transfer, of any size, and the ceiling above was only ever
		// about the header block. Same reasoning as handle's own release, and
		// the same small caveat — bufio fills ahead, so at most one buffer's
		// worth of what followed the header went unmetered.
		lim.limited = false
		idleSpent += time.Since(headStart)
		// Handed to the rolling clock rather than cleared, which is what the
		// first pass did — and clearing it is the whole of the slow variant.
		clock.rolling.Store(true)
		clock.arm(bodyStallTimeout)
		if err != nil {
			if overBudget {
				// Answered rather than dropped. The guest can act on this one:
				// it sent a header block larger than the proxy will parse, and
				// nothing about that is ambiguous. Recorded either way, since
				// a refusal nobody can see is not much of a refusal.
				//
				// Its own reason, not bad_request. bad_request says the proxy
				// could not parse the request; this says it refused to, and an
				// operator reading the chain wants to tell a broken client
				// from one sending four mebibytes of headers.
				//
				// The connection summary below still reports allowed and
				// mode=terminated, and that is correct rather than an
				// oversight: it is a statement about the CONNECTION, which
				// policy did permit and which the proxy did decrypt. A
				// connection that carried three good requests before the
				// fourth was refused would be described worse, not better, by
				// allowed=false — and would lose the byte counts that make the
				// receipt worth having. "Connection allowed, request refused"
				// is two events here, as it is everywhere else on this leg.
				p.report(Attempt{Host: host, Port: port, Reason: ReasonHeaderTooLarge})
				writeStatus(clock, http.StatusRequestHeaderFieldsTooLarge,
					"kelyfos: request header block is larger than this proxy will parse")
				// Then a short, bounded drain before closing. The guest is
				// still pushing the rest of that header when the refusal is
				// written, and closing a socket with unread data in it sends a
				// reset that discards what was just written — so without this
				// the 431 is composed, sent, and thrown away by the kernel,
				// which is the same "refusal nobody can see" this branch
				// exists to avoid. Discarded, never retained, and bounded in
				// both bytes and time so draining cannot become the hold the
				// budget just refused.
				clock.rolling.Store(false)
				clock.arm(refusalDrainTimeout)
				_, _ = io.CopyN(io.Discard, inner, refusalDrainBytes)
				break
			}
			if !errors.Is(err, io.EOF) && in == 0 && out == 0 {
				p.report(Attempt{Host: host, Port: port, Reason: ReasonBadRequest})
				return
			}
			break
		}
		req.URL.Scheme = "https"
		req.URL.Host = upstreamAddr
		req.RequestURI = ""

		// The credential goes only to the host this connection was opened,
		// verified and recorded against.
		//
		// This is not a new rule, it is a defect being closed. http.ReadRequest
		// fills req.Host from the guest's own Host: header, and Go's
		// Request.write prefers req.Host over req.URL.Host — so setting the URL
		// host above does not change the header on the wire. A guest could
		// CONNECT to a bound domain, get the certificate for it, and then
		// address the credentialed request to any other name it liked:
		//
		//	dialled and TLS-verified : api.github.com:443   (the bound host)
		//	Host: on the wire        : whatever it chose
		//
		// On a virtual-hosted or shared-edge origin that routes on Host, the
		// bound credential is then presented to a different site — and the
		// record named the CONNECT target, so it said the wrong thing too.
		// Measured against Go's own Request.write before being written down.
		//
		// Withheld rather than rewritten: rewriting a guest's Host header would
		// silently change what it asked for, and the request itself is allowed
		// — `allow` decided that. What is refused is the credential.
		secret, why := pick(bound, req, host)
		if secret != nil {
			req.Header.Set("Authorization", secret.Header())
			attached = secret
			// Nothing about a RoundTrip error says whether the request was
			// written, and the two failures underneath one want opposite
			// records. A peer that reads the request and then resets the
			// connection HAS the credential; a dial or handshake that never
			// completed never sent a byte. Recording neither is how a
			// credential leaves the machine with nothing written down;
			// recording both would claim a credential was presented on a
			// request that never went out. WroteHeaders is the only thing that
			// separates them: it fires once the Authorization line has been
			// written to the connection, and nothing calls it on a dial
			// failure, a DNS failure or a TLS handshake failure.
			req = req.WithContext(httptrace.WithClientTrace(req.Context(),
				&httptrace.ClientTrace{WroteHeaders: func() { sent.Store(true) }}))
		} else if len(bound) > 0 && p.OnWithheld != nil {
			// Say so. A credential that silently does not attach sends the
			// request out unauthenticated and the only symptom is a failure
			// from somewhere else.
			p.OnWithheld(bound[0].Name, host, why)
		}

		// Waiting for the ORIGIN is idle time too, and until this it was the
		// one kind that went uncharged (P7-17/B2, review round). The budget
		// above charges the gap between requests and the reading of the header
		// block; RoundTrip sits between the two and was counted by neither, so
		// "ten minutes of cumulative idle across the connection" was true of
		// everything except the wait that can last the longest. D74 raised
		// ResponseHeaderTimeout to ten minutes on the stated ground that the
		// idle budget already bounded this — and it did not, which made
		// ResponseHeaderTimeout the only bound on it and D74's own reasoning
		// false. Charging it is what makes the sentence true.
		//
		// Charged after the fact rather than clamped: a wait already under way
		// cannot be shortened without cutting a legitimate slow completion in
		// half, and a cumulative budget's job is to stop the connection doing
		// it AGAIN. So one request may spend up to ResponseHeaderTimeout on a
		// silent origin, and the connection is then out of budget and does not
		// get a second.
		//
		// touch() for the same reason it is called on every other kind of
		// progress: a proxy waiting on an origin is a sandbox doing something,
		// and `--idle-timeout` reaps on Proxy.LastActive(). Without it the very
		// call D74 exists to permit — a model API taking minutes to its first
		// byte — can have the sandbox reaped out from under it.
		upstreamStart := time.Now()
		resp, err := p.upstream().RoundTrip(req)
		idleSpent += time.Since(upstreamStart)
		p.touch()
		// The event is owed to the credential having left, not to an answer
		// coming back. Reporting it only on success made the record miss every
		// credential the peer took and then reset on — a failure ordinary
		// network flakiness reaches, and one where the reader most needs to
		// know the token is out there.
		if attached != nil && p.OnSecret != nil && (err == nil || sent.Load()) {
			p.OnSecret(attached.Name, host)
		}
		if err != nil {
			p.reportDialFailure(clock, host, port, err)
			return
		}
		p.scrubResponse(resp, host)
		// A chunked body reports -1, which is not a byte count. Adding it
		// walked the receipt backwards; an unknown length contributes nothing
		// rather than subtracting (F-D33).
		if req.ContentLength > 0 {
			out += req.ContentLength
		}
		if resp.ContentLength > 0 {
			in += resp.ContentLength
		}
		// A response whose length is indeterminate is framed by the connection
		// closing, so the loop must not carry on waiting for another request:
		// the client would sit there until its own timeout with the whole body
		// already in hand.
		indeterminate := resp.ContentLength < 0 && resp.TransferEncoding == nil
		// Through the clock, not straight at the connection: this is the write
		// a guest can block by not reading (F16).
		werr := resp.Write(activeWriter{clock, p})
		resp.Body.Close()
		// resp.Close and req.Close are load-bearing beyond keep-alive
		// bookkeeping, and the next person to tidy this line should know it:
		// an origin that answers without reading the request body sets
		// Connection: close, and this break is what stops the loop reaching a
		// second Peek while the transport's goroutine may still be draining
		// the first request's body through the same reader. Remove it and that
		// becomes a live race rather than an unreachable one.
		if werr != nil || indeterminate || resp.Close || req.Close {
			break
		}
	}

	p.report(Attempt{
		Host: host, Port: port, Allowed: true, Mode: ModeTerminated,
		BytesIn: in, BytesOut: out,
	})
}

// The bounds one terminated connection lives under.
//
// A terminated connection is the expensive kind: the proxy has decrypted it, it
// is holding a credential for it, and it is occupying one of
// maxConcurrentConnections slots. Nothing before this stopped a guest opening
// one and keeping it forever.
const (
	// maxRequestsPerTerminatedConn caps how many requests one tunnel may
	// serve. Generous — no real client sends four thousand requests down one
	// connection to one host in a session — and it is what stops a guest that
	// keeps a connection legitimately busy from keeping it busy indefinitely.
	maxRequestsPerTerminatedConn = 4096
	// terminatedIdleTimeout is how long the guest may leave a tunnel silent
	// between two requests. Long enough for a client that thinks between
	// calls, which is exactly what readHeaderTimeout is too short for.
	terminatedIdleTimeout = 2 * time.Minute
	// maxTerminatedIdleTotal is all those gaps added together, plus the time
	// spent reading the request headers themselves. Without it, a guest could
	// park a connection for just under terminatedIdleTimeout, send one byte,
	// and park it again, forever — a slot and a credential held for the cost
	// of a byte every two minutes.
	//
	// The header read is charged too, and that is not a detail: charging only
	// the gaps bounded silence rather than occupancy, so 4096 requests each
	// spending 9.9 seconds inside readHeaderTimeout came to over eleven hours
	// of held slot while this budget barely moved.
	maxTerminatedIdleTotal = 10 * time.Minute
	// bodyStallTimeout is how long a request body may produce nothing before
	// the connection is closed. It is armed again on every read, so it bounds a
	// stall without bounding a transfer — the same distinction the header and
	// gap bounds make, applied to the one part of a request that has no
	// natural size.
	//
	// This is what the first pass at F16 missed. The header bounds were set
	// and then cleared before the body and nothing re-armed them, so a guest
	// that sent a request declaring a megabyte and then dribbled held the
	// tunnel open — decrypted, holding the credential, holding one of
	// maxConcurrentConnections slots — for as long as it cared to trickle.
	// The finding said so in its own words: "a byte a minute holds the slot
	// forever."
	//
	// The same ten seconds readHeaderTimeout uses, and for the same reason:
	// this leg is a guest on a local virtio link, not a person on a train.
	// Ten seconds of a body producing nothing at all is a stall, not slowness.
	// A stall bound is not a throughput bound and cannot be one — a guest that
	// dribbles just fast enough to keep re-arming it is bounded by
	// maxTerminatedConnTime below, not by this.
	bodyStallTimeout = 10 * time.Second
	// maxTerminatedConnTime is the ceiling on the whole connection, however
	// the time is spent. A rolling stall bound cannot reach a guest that
	// dribbles just fast enough to keep re-arming it — that is the nature of a
	// stall bound, not a defect in it — so occupancy gets a limit that does not
	// care whether the time was silent, slow or busy. Generous for any real
	// exchange with one origin; a guest that needs longer opens another
	// connection, which costs it a handshake and costs the record an entry.
	maxTerminatedConnTime = time.Hour
	// refusalDrainBytes and refusalDrainTimeout bound the drain that lets a
	// refusal survive the close. See the 431 branch in terminate.
	refusalDrainBytes   = 1 << 20
	refusalDrainTimeout = 2 * time.Second
)

// terminatedTransport is the upstream leg for terminated connections.
//
// Compression is disabled deliberately. Go's default transport adds
// "Accept-Encoding: gzip" and transparently decompresses the reply, which is
// convenient for a client and wrong for a proxy: it discards the original
// Content-Length and leaves a response that can only be framed by closing the
// connection. Passing bytes through as the server sent them keeps the framing
// the client expects — and keeps keep-alive working.
// DialContext is dialContextSafe, not net/http's own default dialer: it
// carries the same resolved-address check tunnel and forwardHTTP use, so a
// secret-bound domain that is DNS-hijacked onto loopback, link-local or other
// private/reserved space is refused here too, before the connect syscall
// that would otherwise let a bound credential reach it (F2).
//
// Proxy is absent, and stays absent: this transport was already built from a
// zero value rather than cloned, which is why it never had F15's inherited
// HTTP_PROXY. The bounds below are new with F15 all the same — a zero-value
// transport gets no MaxIdleConns, no idle reaping and no TLS handshake
// timeout, and zero means unbounded for each. The forward transport had those
// by accident, from the clone; this one had never had them at all.
//
// ExpectContinueTimeout is not one of them, and saying otherwise was a mistake
// worth correcting rather than quietly deleting: Go's doc says zero means no
// timeout "and causes the body to be sent immediately, without waiting for the
// server to approve". Zero is the absence of a wait. One second is still the
// right value; it just is not closing a hole.
//
// ResponseHeaderTimeout was in neither transport and is in neither Go default.
// It is the one that matters most here: this is the leg carrying the
// credential, and an origin that accepts, completes TLS and then says nothing
// would otherwise hold the slot and the credential indefinitely.
//
// **It is the only bound on that wait**, and saying otherwise was this
// change's own mistake (D74 as amended, P7-17/B2 review round). The first
// version of this comment said the raise to ten minutes only made the
// transport "agree with a bound already in force" — the cumulative idle budget
// and the connection ceiling. Measured, neither reached it: the budget charged
// the gap between requests and the header read and not the RoundTrip between
// them, and notAfter clamps to the one-hour ceiling and never fires during a
// wait in which no I/O happens on the guest connection at all. A probe on a
// two-second idle budget was answered after six seconds.
//
// terminate now charges the RoundTrip to the budget, which makes the sentence
// true going forward: one request may spend up to this long on a silent origin,
// and the connection is then out of budget and does not get a second. This
// value is what bounds the FIRST such wait, and it is a deliberate choice about
// how long an allowlisted origin may hold a goroutine, a socket, a slot and —
// here — a credential. Ten minutes rather than thirty seconds because this is
// the credentialed model-API path and a non-streaming completion that takes
// longer than thirty seconds to its first byte is ordinary rather than hostile.
// The forward transport carries the same number and has none of the machinery
// above, which is why removing the field was rejected there.
var terminatedTransport = &http.Transport{
	DisableCompression:  true,
	ForceAttemptHTTP2:   false,
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 4,
	TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
	DialContext:         dialContextSafe,

	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: maxTerminatedIdleTotal,
}

func (p *Proxy) upstream() http.RoundTripper {
	if p.Upstream != nil {
		return p.Upstream
	}
	return terminatedTransport
}

// sameHost reports whether a request's Host header names the host the
// connection was opened to. An empty Host is fine: Go then falls back to
// req.URL.Host, which is the CONNECT target itself.
func sameHost(reqHost, bound string) bool {
	if reqHost == "" {
		return true
	}
	h := reqHost
	if only, _, err := net.SplitHostPort(h); err == nil {
		h = only
	}
	return strings.ToLower(strings.TrimRight(h, ".")) == bound
}

// pick chooses which bound credential, if any, may be attached to one request,
// and says why when none may.
//
// Declaration order decides between two secrets that both cover a request: the
// policy file is read top to bottom and the first binding that fits wins, which
// is the rule a person can predict without knowing how prefixes compare.
func pick(bound []*Secret, req *http.Request, host string) (*Secret, string) {
	// The host check comes first and applies to all of them: a request that
	// addresses another name is not inside anybody's scope.
	if !sameHost(req.Host, host) {
		return nil, WithheldHostMismatch
	}
	why := ""
	for _, s := range bound {
		if ok, reason := s.Scope.covers(req); ok {
			return s, ""
		} else if why == "" {
			why = reason
		}
	}
	return nil, why
}
