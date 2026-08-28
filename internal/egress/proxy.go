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
	"net/netip"
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
	// ModeDirectTLS: an absolute-form request whose target scheme is https,
	// sent straight to this proxy without a CONNECT first — a request line
	// RFC 7230 §5.3.2 permits and forwardHTTP has always accepted. The proxy
	// performs the fetch itself, over a real, certificate-validated TLS
	// connection to the origin, so it read all of it, exactly as it does for
	// ModePlain — but unlike ModePlain, something here genuinely was
	// encrypted: the leg the proxy itself ran to reach the origin. Recording
	// it as ModePlain would be F-D33's understatement again, the other way
	// round: ModePlain's own doc says "nothing was encrypted", which is false
	// on this path (S5d).
	ModeDirectTLS = "direct_tls"
)

// Reasons recorded when a connection is refused.
const (
	ReasonNotAllowed = "not_in_allowlist"
	ReasonBadPort    = "port_not_allowed"
	ReasonBadRequest = "bad_request"
	ReasonDialFailed = "upstream_unreachable"
	ReasonPinned     = "tls_pinning_rejected_our_ca"
	// ReasonUnsafeResolvedAddr is a dial refused after resolution: the
	// allowlisted host named a domain, and that domain resolved to loopback,
	// link-local (169.254.0.0/16 — cloud instance metadata — included) or
	// other private/reserved space (F2). allowsHost only ever looked at the
	// hostname string; this is the check that looks at where it actually
	// leads.
	ReasonUnsafeResolvedAddr = "unsafe_resolved_address"
	// ReasonForeignPeer is a connection refused before anything was read from
	// it, because it did not come from the sandbox this proxy serves (F9). It
	// is the only reason on this list that says nothing about what was asked
	// for — the request was never parsed, so Host and Port are empty and the
	// address the connection came from is in Attempt.Peer instead.
	//
	// It is recorded rather than dropped silently because a connection from
	// somewhere else to this port is not a policy question, it is an event: the
	// port carries the operator's credentials, and something on the machine
	// that is not the guest just knocked on it. It is recorded and not printed
	// during the run: blockedOnce prints the refusals that carry a fix line the
	// reader can act on, and this one has none — it is a fact about the host,
	// not about the policy.
	//
	// The address is in the chain and is NOT YET RENDERED anywhere, which is
	// worth saying plainly because the sentence that used to sit here claimed
	// the opposite. An `egress.attempt` carrying reason=foreign_peer and
	// peer=127.0.0.1 prints today as `egress BLOCKED :0  mode= foreign_peer`
	// in `kelyfos log`, as `egress BLOCKED :0` in `kelyfos view` — which does
	// not print the reason at all — and lands in the digest as one more
	// egress_blocked. None of the four branches that render this event type
	// read Event.Peer: host/log.go:818, host/view.go:580, host/watch.go:539
	// and internal/report/report.go:397 and :604. Until they do, a foreign-peer
	// refusal is indistinguishable on screen from an ordinary blocked egress
	// with an empty host, and only `kelyfos log --export` or reading the chain
	// itself shows who knocked. Those four branches are F20's surface, and the
	// change is routed there rather than made here.
	ReasonForeignPeer = "foreign_peer"
)

// WithheldNotViaConnect belongs beside scope.go's own WithheldPath,
// WithheldNotPlain, WithheldUnencrypted and WithheldHostMismatch — it is the
// same vocabulary, for the same OnWithheld callback — but scope.go is mid-edit
// for a separate, already-closed finding at the time of this one, so this
// constant is declared here instead rather than adding a second hand to that
// file's diff.
//
// It is for exactly the request ModeDirectTLS records: an absolute-form
// https:// request that reached forwardHTTP directly, never sending a
// CONNECT. The connection to the origin is genuinely TLS-protected there, so
// WithheldUnencrypted would be a false statement about it — what is actually
// true is narrower: credential injection is wired only into the
// CONNECT+terminate path (decision D6), and this path never reaches it,
// encrypted or not (S5d).
const WithheldNotViaConnect = "not_via_connect"

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
	// Peer is who connected, for ReasonForeignPeer and for nothing else — the
	// address a refused connection came from. Appended as its own field rather
	// than folded into Host, which was the first attempt and was wrong: five
	// readers treat Host as a destination — internal/digest enters it in the
	// Domains table and counts it Blocked, internal/report titles the row
	// "BLOCKED "+Host, and log, view and watch all print it as somewhere the
	// sandbox tried to reach. A source address in that field makes every one of
	// them say the guest named a host it never named, and in the digest it also
	// consumes one of MaxDistinctKeys, so foreign traffic could evict the
	// guest's own blocked-domain records. recorder.Event already has a peer
	// field, which is where this lands.
	Peer string
	// ResolvedAddr is where an allowlisted name actually resolved to, on a
	// ReasonUnsafeResolvedAddr refusal and nothing else. It goes to the
	// recorder and never into the body the guest reads (F14).
	ResolvedAddr string
}

// DefaultPorts is what every sandbox in this product gets: the two ports the
// proxy carries when a Policy names none of its own. It is exported, named
// and tested rather than left as the two bare integers `allowsPort` used to
// compare against, because nothing before P7-4 gave a reader — a person or a
// future view rendering a Policy — anywhere to look this up. No caller in
// production code ever sets Policy.Ports (tests do — see the Ports field
// below); every sandbox this product boots is on this default, and
// docs/networking.md §6 and EgressPort's own fix line (internal/denial) both
// say so. See P7-4 for why this stayed a fixed property instead of becoming
// a kelyfos.toml key: opening egress to arbitrary ports is a bigger and more
// security-relevant surface than anything demanded it, so the smaller
// change — making the existing fixed pair discoverable — is what shipped
// (D65).
//
// A function returning a fresh slice each call, not an exported var: a shared
// backing array would let one caller's in-place edit of what it thinks is its
// own copy corrupt the default for every Policy that ever falls back to it.
func DefaultPorts() []int { return []int{80, 443} }

// Policy decides what may leave.
type Policy struct {
	// Allow lists permitted hostnames. A bare hostname matches itself and its
	// subdomains, so "github.com" also permits "api.github.com" — which is what
	// someone typing --allow github.com means, and refusing it would only teach
	// them to pass a wildcard.
	Allow []string
	// Ports that may be reached. Empty means DefaultPorts (80 and 443). No
	// caller in this codebase ever sets this outside a test — see DefaultPorts.
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

// EffectivePorts is what this Policy actually enforces: Ports when the policy
// names its own, DefaultPorts otherwise. Reading Policy.Ports directly gives
// the wrong answer for the common case — nil, which looks like "no port is
// permitted" rather than "the fixed default applies" — which is exactly the
// trap a future reader of the record (P7-2's session.policy) or a view
// (P7-7/P7-8) would fall into without this (P7-4).
//
// Both branches return a slice this Policy does not itself hold a reference
// into: the custom-Ports branch copies rather than returning p.Ports itself,
// for the same reason DefaultPorts is a function and not a shared var — a
// caller that mutated what it got back would otherwise mutate this Policy's
// own Ports in place, and a port check made after that would silently be
// checking against a different policy than the one that was configured
// (found in review).
func (p *Policy) EffectivePorts() []int {
	if len(p.Ports) > 0 {
		return append([]int(nil), p.Ports...)
	}
	return DefaultPorts()
}

func (p *Policy) allowsPort(port int) bool {
	for _, allowed := range p.EffectivePorts() {
		if port == allowed {
			return true
		}
	}
	return false
}

// Proxy is an HTTP proxy that enforces a Policy and reports every attempt.
type Proxy struct {
	Policy Policy
	// Peer is the single address this proxy will serve: the guest's own TAP
	// address, `Network.GuestIP`. Every connection from anywhere else is closed
	// before a byte is read from it and recorded as ReasonForeignPeer.
	//
	// This check exists because the address the proxy binds does not do the
	// work the code here used to claim it did. An address on the TAP is still a
	// local address of the host, so a connection to it from a local process
	// never reaches the TAP at all — the kernel routes it over `lo`, where the
	// firewall's `iifname` match has no opinion about it — and the proxy would
	// then attach the operator's credential for whoever asked. Measured, not
	// reasoned about: a local process dialling the bound address is answered,
	// and the source address the kernel picks for it is the host's own end of
	// the /30 (F9).
	//
	// Set it. A zero Addr means no peer restriction at all, which is what every
	// test in this package wants and what no sandbox does. The ruleset's own
	// `ip daddr <host> iifname != <tap> drop` covers the same ground from the
	// other side, and each is there for the day the other is wrong.
	//
	// Five callers build a Proxy and bind it on a TAP address, and all five set
	// this from the Network they already hold — host/run.go, host/team.go,
	// host/servemcptools.go, host/snapshot.go and shim/shim.go, each with
	// `Peer: <net>.GuestAddr()`. That is not left to review:
	// TestF9_EveryProxyConstructionArmsThePeerCheck reads every non-test .go
	// file in the repository and fails on each construction of this type that
	// does not set Peer in its own composite literal. The first pass at F9
	// shipped this field with nothing setting it — a check that existed, was
	// tested, and defended nothing — and the first pass at that test excused a
	// whole file if any `X.Peer` appeared in it, which recorder.Event provides
	// for free.
	//
	// What it does not cover, stated because a guarantee is only worth what its
	// edges are, and because the first version of this list was wrong in the
	// same way the Listen comment was. It reads syntax, not types, so it sees a
	// Proxy only where the source names one: it resolves import aliases, dot
	// imports, the in-package spelling, local aliases and defined types,
	// elided element types in slice, array and map literals, elided values of
	// Proxy-typed struct fields declared in the same package, new() and zero
	// var declarations, and it refuses outright a struct that embeds Proxy,
	// because embedding hides the construction from any syntactic check. It
	// does NOT cover: _test.go files; a type declared in ANOTHER package that
	// embeds or aliases Proxy; type parameters; and any construction that
	// reaches a Proxy through an interface or reflection. The one test proxy
	// that binds a real TAP address sets Peer by hand for the first of those.
	Peer    netip.Addr
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

	// sem bounds how many client connections are being served at once (S5a).
	// Serve creates it lazily so a Proxy built without Listen's other setup
	// still works. Acquired before Accept, not after, so a proxy already at
	// capacity blocks *there* — throttling acceptance itself, not just how
	// many goroutines pile up behind it.
	sem chan struct{}

	// foreignSeen is the set of addresses a foreign_peer event has already been
	// written for, so a refusal loop costs one event rather than one per
	// connection. See maxForeignPeersRecorded.
	foreignMu   sync.Mutex
	foreignSeen map[string]bool

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

// Listen binds the proxy. The address is the host's TAP address.
//
// That address is not what keeps the port private, and this comment used to say
// it was: "the proxy is reachable from exactly one sandbox and from nothing
// else on the machine". It was false, and being written here is part of why the
// first security pass read it and marked credential injection sound. An address
// on a TAP is a local address like any other — every process on the host can
// route to it over `lo`, without a packet ever reaching the interface the
// firewall inspects.
//
// Two checks make the sentence true, and neither of them is the bind address:
//   - Peer, below in handle: one address is served and every other connection
//     is closed unread and recorded (F9).
//   - `ip daddr <host_ip> iifname != "<tap>" counter drop` in the input chain,
//     so the port is unreachable even from a proxy that forgot the first check
//     (docs/networking.md §3).
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

// maxConcurrentConnections bounds how many client connections Serve will
// service at once. A sandbox's egress traffic is one guest's, not a public
// server's, so this is generous for real parallel work — many simultaneous
// package downloads or API calls — while still bounding the worst case: a
// guest that opens far more connections than this cannot make Serve spawn
// more than this many goroutines, however many it opens or however slowly
// each one speaks (S5a).
const maxConcurrentConnections = 128

// Serve accepts until Close.
func (p *Proxy) Serve() {
	if p.sem == nil {
		p.sem = make(chan struct{}, maxConcurrentConnections)
	}
	for {
		// Acquired before the next Accept, not after: once maxConcurrentConnections
		// goroutines are outstanding this send blocks, and Serve does not call
		// Accept again until one of them finishes and releases its slot. That is
		// the whole mechanism — a guest holding the cap in connections it never
		// finishes leaves its own next connection unaccepted, not merely queued
		// behind an ever-growing pile of goroutines (S5a).
		p.sem <- struct{}{}
		conn, err := p.ln.Accept()
		if err != nil {
			<-p.sem
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.sem }()
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

// readHeaderTimeout bounds how long a connection may take to finish sending a
// request before the proxy gives up on it. This is a guest→proxy concern, and
// a different one from DialTimeout, which bounds the proxy→upstream leg: a
// guest that opens a connection and never finishes a request line otherwise
// holds a goroutine, a buffer and an accepted socket forever, one of the
// maxConcurrentConnections slots spent for good. Ten seconds is generous for
// this link — every real client here is a library handing over a request it
// already assembled in memory over a local, single-hop TAP, not a person
// typing at a terminal — and short enough that flooding empty connections
// cannot hold the cap's slots for long (S5a).
const readHeaderTimeout = 10 * time.Second

// maxRequestHeaderBytes bounds how many bytes http.ReadRequest may consume
// trying to parse one request off the wire. http.ReadRequest enforces no such
// limit itself — net/http's own Server does, but this package talks to
// net.Conn directly, so nothing did — and an unbounded request line or header
// block is unbounded memory per connection while it parses. Sized like
// internal/proto's own guest-facing ceilings (MaxLine is 1 MiB): far more than
// any real request line and header block need, and small enough that
// maxConcurrentConnections of them at once is nowhere near a problem. A
// request whose headers do not fit is refused as ReasonBadRequest below,
// exactly like any other request this proxy cannot parse (S5a).
const maxRequestHeaderBytes = 1 << 20

// headerLimitReader bounds bytes read while active, then passes every further
// read straight through once released.
//
// A plain io.LimitReader will not do here: http.ReadRequest's returned
// req.Body reads from the exact reader passed to it, so a bufio.Reader built
// over a plain io.LimitReader keeps charging a plain-HTTP or direct-TLS
// request's BODY against the same budget meant only for its headers — a real,
// found-in-review regression, since a request whose header+body together
// crossed maxRequestHeaderBytes had its body silently truncated mid-transfer
// even though nothing here was ever meant to cap body size. Releasing the
// limit the moment http.ReadRequest returns fixes that: the only bytes ever
// charged against the header budget are the request line and header block,
// plus at most one bufio.Reader-internal-buffer's worth of whatever came
// after (bufio fills ahead of what a caller asked for) — negligible against a
// 1 MiB budget and never repeated, since every read after release is
// unbounded, matching this proxy's pre-existing, uncapped body handling.
type headerLimitReader struct {
	r       io.Reader
	n       int64
	limited bool
}

func (h *headerLimitReader) Read(p []byte) (int, error) {
	if !h.limited {
		return h.r.Read(p)
	}
	if h.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > h.n {
		p = p[:h.n]
	}
	n, err := h.r.Read(p)
	h.n -= int64(n)
	return n, err
}

// foreignPeer reports whether this connection came from somewhere other than
// the sandbox, and records the refusal when it did. It is the first thing
// handle does, before a deadline is set or a byte is read, because everything
// after it either reads what the caller sent or attaches a credential on the
// caller's behalf, and neither should happen for a caller that is not the guest.
//
// Fail closed: a remote address this cannot resolve to an IP is refused rather
// than let through. The published fix for F9 dereferenced the type assertion
// before testing whether it succeeded, which would panic on the one case the
// check is there to catch.
func (p *Proxy) foreignPeer(client net.Conn) bool {
	if !p.Peer.IsValid() {
		return false
	}
	ra, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		p.reportForeignPeer("")
		return true
	}
	peer, ok := netip.AddrFromSlice(ra.IP)
	// Unmap on both sides: a caller setting Peer from a net.IP holding an
	// IPv4-in-IPv6 form and a v4 connection arriving as four bytes are the same
	// address, and comparing the netip.Addr values without unmapping says they
	// are not — which would refuse the guest.
	if !ok || peer.Unmap() != p.Peer.Unmap() {
		var from string
		if ok {
			from = peer.Unmap().String()
		}
		p.reportForeignPeer(from)
		return true
	}
	return false
}

// maxForeignPeersRecorded bounds how many distinct addresses this proxy will
// ever write a foreign_peer event for.
//
// Every other refusal on this proxy costs the guest a request it had to
// assemble and send; this one costs a local process a TCP handshake, and it can
// drive it in a tight loop from as many source addresses as the host has —
// 127.0.0.0/8 alone is sixteen million. Without a bound that is an unbounded,
// unprivileged, cheap write into the flight recorder, and through the digest's
// own MaxDistinctKeys it would evict the records the operator actually wants.
//
// So: one event per distinct address, and past this many distinct addresses,
// none. The same shape and the same failure mode as host/denials.go's
// maxBlockedEntries — "no more new lines", never unbounded memory — and sized
// far above the handful of local addresses a real machine answers on.
const maxForeignPeersRecorded = 256

// reportForeignPeer records the refusal, once per distinct peer, without going
// through report.
//
// Not through report because report touches lastActive, and lastActive is what
// the idle timeout reads (E1-6). A connection from a process that is not the
// guest is not the guest doing something, and letting it advance that clock
// would hand any local process a way to keep an idle sandbox alive
// indefinitely — a smaller door than F9's, opened by the fix for it.
func (p *Proxy) reportForeignPeer(from string) {
	if p.OnEvent == nil {
		return
	}
	p.foreignMu.Lock()
	if p.foreignSeen == nil {
		p.foreignSeen = map[string]bool{}
	}
	if p.foreignSeen[from] || len(p.foreignSeen) >= maxForeignPeersRecorded {
		p.foreignMu.Unlock()
		return
	}
	p.foreignSeen[from] = true
	p.foreignMu.Unlock()
	p.OnEvent(Attempt{Reason: ReasonForeignPeer, Peer: from})
}

func (p *Proxy) handle(client net.Conn) {
	defer client.Close()
	if p.foreignPeer(client) {
		// Closed with nothing written back. A caller that is not the sandbox
		// gets no status line, no fix line and no evidence of what is behind
		// this port — everything the guest is told exists to help the guest,
		// and this one is not the guest.
		return
	}
	p.touch()
	// Set before anything is read, so a connection that never finishes sending
	// a request is closed by the deadline rather than held open indefinitely
	// (S5a). The error path below already reports and returns on whatever
	// http.ReadRequest hands back when this fires, so it needs no handling of
	// its own.
	_ = client.SetReadDeadline(time.Now().Add(readHeaderTimeout))
	limited := &headerLimitReader{r: client, n: maxRequestHeaderBytes, limited: true}
	br := bufio.NewReader(limited)

	req, err := http.ReadRequest(br)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			p.report(Attempt{Reason: ReasonBadRequest})
		}
		return
	}
	// Both the header deadline and the header byte budget were only ever
	// about the guest finishing a request; whatever tunnel, terminate or
	// forwardHTTP does next is a legitimate, possibly long-lived transfer —
	// of a body that can be any size — and must inherit neither a ten-second
	// clock nor a 1 MiB ceiling.
	_ = client.SetReadDeadline(time.Time{})
	limited.limited = false

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
	// dialerFor is what checks the address host actually resolves to before
	// this connects to it (F2): allowsHost above only ever looked at the
	// hostname string a guest's CONNECT named, never at where DNS sends it.
	upstream, err := dialerFor(host, p.DialTimeout).Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		p.reportDialFailure(client, host, port, err)
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
	// Captured before the fallback below can overwrite it. An absolute-form
	// request line already carries its own scheme: "GET https://host/path
	// HTTP/1.1" sent straight to this proxy, with no CONNECT first, is a
	// request line RFC 7230 §5.3.2 permits and this function has always
	// accepted, and when that scheme is https, RoundTrip below genuinely
	// dials the origin over a real, certificate-validated TLS connection.
	// Both the withheld reason and the mode recorded further down have to be
	// decided from the scheme the request actually named, not from
	// req.URL.Scheme after the fallback has already turned an absent one into
	// "http" (S5d).
	effectiveScheme := req.URL.Scheme
	if effectiveScheme == "" {
		effectiveScheme = "http"
	}

	// A credential is never attached to a request this function handles:
	// injection is wired only into the CONNECT+terminate path (decision D6).
	// That is right for the genuinely plain case — nobody should put a bearer
	// token on an unencrypted request — and WithheldUnencrypted says so
	// accurately. It would be a false statement on the https branch, where the
	// fetch this function performs is genuinely TLS-protected end to end; what
	// is actually true there is narrower — this code path simply has no
	// injection point of its own, encrypted or not — so it gets its own
	// reason instead (P6-4, S5d).
	if bound := p.Policy.secretsFor(host); len(bound) > 0 && p.OnWithheld != nil {
		reason := WithheldUnencrypted
		if effectiveScheme == "https" {
			reason = WithheldNotViaConnect
		}
		p.OnWithheld(bound[0].Name, host, reason)
	}
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	// forwardTransport, not http.DefaultTransport: its DialContext carries the
	// same resolved-address check tunnel and terminate's upstream leg use, so
	// this path cannot be the one an allowlisted-but-DNS-hijacked domain
	// reaches a private address through (F2).
	resp, err := forwardTransport.RoundTrip(req)
	if err != nil {
		p.reportDialFailure(client, host, port, err)
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
	// Plain unless the target scheme was https, in which case RoundTrip just
	// performed a real TLS handshake to fetch it. Recording that as ModePlain
	// would repeat F-D33's mistake in the other direction: ModePlain's own doc
	// says "nothing was encrypted", and here something genuinely was (S5d).
	mode := ModePlain
	if effectiveScheme == "https" {
		mode = ModeDirectTLS
	}
	p.report(Attempt{Host: host, Port: port, Allowed: true, Mode: mode,
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
	// RFC 1035 §3.1 bounds a hostname to 253 bytes. Nothing above checks
	// length, only characters, and what comes back from here is eventually
	// written into the flight recorder as an egress.attempt's Host — so a
	// garbage "hostname" built from megabytes of `plausibleHost`-legal
	// characters used to reach the record whole. Checked here, before
	// plausibleHost's per-character loop, and with a message that never echoes
	// the oversized string: a `%q` of a multi-megabyte host would balloon both
	// this error and the body writeStatus sends back to the guest (S1).
	if len(host) > maxHostnameBytes {
		return "", 0, fmt.Errorf("host is %d bytes, over the %d-byte limit", len(host), maxHostnameBytes)
	}
	if !plausibleHost(host) {
		return "", 0, fmt.Errorf("bad host %q", host)
	}
	return host, port, nil
}

// maxHostnameBytes is RFC 1035's limit on a fully-qualified hostname.
const maxHostnameBytes = 253

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
