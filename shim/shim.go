// Package shim serves an E2B-compatible REST subset in front of KelyfOS
// sandboxes, so code already written against the E2B SDK can point at a
// self-hosted box (P3-4).
//
// It is a **best-effort subset**, not a reimplementation. E2B's control API and
// envd file endpoints are ordinary HTTP and are implemented here; command
// execution in the current SDK goes over Connect RPC with protobuf streaming,
// which is a different protocol stack and is deliberately out of scope. What
// works is documented in docs/e2b-shim.md; what does not returns a clear error
// rather than a confusing one.
package shim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ikapa-dev/kelyfos/internal/egress"
	"github.com/ikapa-dev/kelyfos/internal/proto"
	"github.com/ikapa-dev/kelyfos/internal/recorder"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
	"github.com/ikapa-dev/kelyfos/internal/sessionpolicy"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// EnvdVersion is what the shim reports to the SDK. The SDK gates features on
// it, so this claims a version whose feature set the shim actually implements
// rather than the newest one.
const EnvdVersion = "0.1.0"

// Policy is the project's kelyfos.toml, resolved once by the CLI and applied to
// every sandbox this shim creates (F-D33).
//
// It exists because an entry path that skips the policy file is a hole in the
// wall, not a convenience. F-D5 already says an MCP tool can never widen policy
// because the toml is the ceiling; the same rule has to hold here, or "the
// policy travels with the project" is true of `kelyfos run` and false of the
// door an SDK comes through.
type Policy struct {
	Arch   string
	Flavor string

	// Allow is the egress allowlist, and Secrets the credentials bound to
	// domains inside it. Both come from the file unless the operator who
	// started the shim named them on the command line.
	Allow   []string
	Secrets []*egress.Secret

	// The caps, exactly as [resources] declares them. There are no per-request
	// knobs: an SDK client cannot ask for a bigger machine, which is the point.
	Vcpus        int
	MemMiB       int
	CPUQuota     int
	IO           sandbox.IOLimits
	ScratchBytes int64

	// Argv and Version are what session.start records about how this shim was
	// launched, so a reader of the chain can reproduce it.
	Argv    []string
	Version string
	// PolicyPath is the file the above came from, empty when there was none.
	PolicyPath string

	// Token is the bearer token every route requires. Empty means the shim
	// authenticates nobody, which since P7-17/F2 happens only when the
	// operator asked for it with --insecure-no-token.
	//
	// The CLI decides it — from KELYFOS_SHIM_TOKEN, or minted — because the
	// CLI is what can print it. This package only compares it.
	Token string

	// Addr is the literal address the listener bound to — net.Listener's own
	// Addr().String(), not the string the operator typed, so `--addr :0` and
	// `--addr localhost:3000` are both resolved before they get here.
	//
	// It is what the Host header is checked against (P7-17/F2). Empty means
	// nobody told this Server what it bound to, and every request is refused:
	// a check that switches itself off when a field is unset is the shape of
	// half the findings in this review.
	Addr string
}

// box is one sandbox the shim owns, with everything that has to come down with
// it. The recorder is per sandbox because a shim sandbox is a session like any
// other: it gets its own chain, opened before the VM starts and closed after it
// stops.
type box struct {
	sb    *sandbox.Sandbox
	rec   *recorder.Recorder
	net   *sandbox.Network
	proxy *egress.Proxy
	slice *sandbox.Slice

	// stopped ends this box's recorder watcher, so it goes away with the
	// machine rather than outliving it (P7-17/A2). The mutex is what makes
	// stopWatching idempotent: close() is reached from the boot unwind, from
	// DELETE /sandboxes/{id}, and from the watcher itself.
	wmu     sync.Mutex
	stopped chan struct{}
}

// stopWatching ends this box's recorder watcher. The channel is taken out of
// the box before it is closed, so a second call finds nothing — the same shape
// serve-mcp's servedBox.stopWatching has, and for the same reason.
func (b *box) stopWatching() {
	b.wmu.Lock()
	stopped := b.stopped
	b.stopped = nil
	b.wmu.Unlock()
	if stopped != nil {
		close(stopped)
	}
}

// watchRecorder stops a sandbox whose flight recorder has failed (P7-17/A2).
//
// This package had zero references to Broken(). F13(b) wired every loop that
// holds a machine open — `kelyfos run`'s two, `team up`'s, `resume`'s,
// `snapshot restore`'s — and gave serve-mcp a per-box watcher because it has no
// such loop. The shim has no such loop either and got neither, so an E2B-shim
// sandbox whose recorder failed went on executing commands and making egress
// with nothing recorded and nobody told: exactly the harm F13 describes, on the
// one door in this product that answers to a network socket.
//
// A goroutine per box, started where the recorder is opened and stopped where
// the box comes down. The SDK is told the way this door tells it anything —
// the machine is gone, so the next call that names it gets a 404 — and the
// operator is told on stderr, immediately, which event was lost.
func (s *Server) watchRecorder(id string, b *box) {
	b.wmu.Lock()
	rec, stopped := b.rec, b.stopped
	b.wmu.Unlock()
	if rec == nil || stopped == nil {
		return
	}
	select {
	case <-stopped:
		return
	case <-rec.Broken():
	}
	seq, ferr := rec.Failure()
	fmt.Fprintf(s.stderr(),
		"kelyfos: the flight recorder for shim sandbox %s stopped at event %d: %v\n"+
			"kelyfos: stopping it — a sandbox nobody is recording is not one this shim keeps "+
			"running\n", id, seq, ferr)

	s.mu.Lock()
	if s.boxes[id] == b {
		delete(s.boxes, id)
	}
	if len(s.lost) < maxLostBoxes {
		if s.lost == nil {
			s.lost = map[string]string{}
		}
		s.lost[id] = fmt.Sprintf("its flight recorder failed at event %d, so it was stopped: "+
			"a sandbox nobody is recording is not one this shim keeps running", seq)
	}
	s.mu.Unlock()

	b.close("recorder_failed")
}

func (b *box) close(reason string) {
	// First, so the watcher does not race the teardown it would otherwise start
	// a second time.
	b.stopWatching()
	// A box can be half-built: boot unwinds through here when it fails, and it
	// can fail before there is a machine to stop — nil-guarded for the same
	// reason serve-mcp's servedBox.close is.
	if b.sb != nil {
		_ = b.sb.Shutdown(5 * time.Second)
	}
	if b.proxy != nil {
		b.proxy.Close()
	}
	if b.net != nil {
		b.net.Down()
	}
	if b.slice != nil {
		b.slice.Close()
	}
	if b.rec != nil {
		// EndBroken before the ordinary session.end, and a no-op on an intact
		// recorder (P7-17/A2). On a broken one the append below is refused like
		// every other, so without this the chain stopped mid-session with
		// nothing saying why; by now the machine is down and whatever was
		// holding the disk may have let go, which is what the second attempt is
		// for. The same order endSession uses on every other door.
		_ = b.rec.EndBroken()
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSessionEnd, Reason: reason,
			DurationMS: b.rec.Since().Milliseconds(),
		})
		_ = b.rec.Close()
	}
}

// Server owns the sandboxes it created. It deliberately does not adopt
// sandboxes started by `kelyfos run`: the SDK's lifecycle expects to own what
// it creates, and killing someone else's interactive session because an SDK
// call said so would be a nasty surprise.
type Server struct {
	Policy Policy

	mu    sync.Mutex
	boxes map[string]*box
	// lost remembers the sandboxes this shim stopped by itself, so the next
	// call naming one is told what happened rather than that it never existed
	// (P7-17/A2, review round). serve-mcp has had this since F13(b), with the
	// stated reason; the shim's watcher deleted the box and kept no reason, so
	// `DELETE /sandboxes/{id}` answered a bare 404 — indistinguishable from a
	// sandbox that was never created — and the envd routes answered 400 "no
	// sandbox has been created through this shim", which is worse.
	//
	// Bounded, because it is a map keyed by something a client can create in a
	// loop. Past the cap the generic message applies, which is what every case
	// got before.
	lost map[string]string

	// errw is where this server's own lines to the operator go. Nil means
	// os.Stderr, which is every real run; a test sets it, because "nobody was
	// told" is half of the harm F13 describes and a line printed to the
	// process's stderr is a line no assertion can reach.
	errw io.Writer
}

// maxLostBoxes bounds the "why is this sandbox gone" map, as serve-mcp's own
// constant of the same name does.
const maxLostBoxes = 32

func New(p Policy) *Server {
	return &Server{Policy: p, boxes: map[string]*box{}}
}

// stderr is where this server's own lines to the operator go.
func (s *Server) stderr() io.Writer {
	if s.errw != nil {
		return s.errw
	}
	return os.Stderr
}

// lostReason is what happened to a sandbox this shim stopped on its own, or ""
// when it never had one. Callers hold s.mu.
func (s *Server) lostReason(id string) string { return s.lost[id] }

// MaxSandboxes is how many machines one shim will hold at once.
//
// A sandbox is a microVM: memory, a disk image, a TAP device, a process. The
// policy carries a ceiling for each of those per machine and, until P6-25, none
// for the number of machines — so the arithmetic was whatever the caller asked
// for times whatever the policy allowed, and the shim is the one door in this
// product another machine can knock on (finding H-6).
//
// Sixteen because the shim is a developer's stand-in for a hosted API on one
// host, not a fleet. A caller that wants more deletes one first, which is a
// request it already has.
const MaxSandboxes = 16

// TokenEnv names the credential the shim requires, when the operator supplies
// one rather than letting the CLI mint one.
//
// Unauthenticated was the documented default until P7-17/F2 and is not any
// more. The argument for it — "the shim is a tool for a machine you already
// trust" — was answering the wrong question: localhost plus no authentication
// is also the configuration a web page can reach, and while the browser checks
// in refuseBrowser close that structurally, every other process on the machine
// could still boot microVMs and write files into a live sandbox for the price
// of knowing the port. A token is now minted per process when this variable is
// unset, and running without one takes --insecure-no-token, because an opt-out
// is a choice the operator can see and an opt-in is a step nobody takes.
const TokenEnv = "KELYFOS_SHIM_TOKEN"

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// envd routes
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /files", s.readFile)
	mux.HandleFunc("POST /files", s.writeFile)
	// control-plane routes
	mux.HandleFunc("POST /sandboxes", s.createSandbox)
	mux.HandleFunc("GET /sandboxes", s.listSandboxes)
	mux.HandleFunc("DELETE /sandboxes/{id}", s.killSandbox)
	mux.HandleFunc("/", s.notImplemented)
	return logging(s.authenticated(mux))
}

// authenticated is every condition that applies to every route, applied once
// rather than per-handler — the browser checks first, then the bearer token
// when one is configured.
//
// The order is the point. A page that somehow learned the token still gets
// nowhere, and the answer a browser receives never depends on a credential
// comparison at all.
//
// The token comparison is constant-time. A token checked with == leaks its
// length and its prefix to anything that can time a request, and a credential
// compared carelessly is the kind of thing this repository spends a whole
// document refusing to do elsewhere.
func (s *Server) authenticated(next http.Handler) http.Handler {
	want := s.Policy.Token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if why := s.refuseBrowser(r); why != "" {
			writeErr(w, http.StatusForbidden, why)
			return
		}
		if want == "" {
			next.ServeHTTP(w, r)
			return
		}
		got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeErr(w, http.StatusUnauthorized,
				"this shim requires a bearer token on every route; the one it minted was printed when it started")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseBrowser makes a web page structurally unable to reach this shim, and
// returns why when it refuses (P7-17/F2).
//
// The shim serves on 127.0.0.1:3000, which is the exact configuration a page
// the developer visits can reach, and two of its routes need no preflight to
// get there: multipart/form-data is a CORS-"simple" request, so a plain <form>
// POSTs a file into the live sandbox, and POST /sandboxes boots a microVM. The
// responses are not readable cross-origin, which does not help: the writes
// land, and a planted file the agent will later read is the better outcome for
// an attacker anyway.
//
// Three checks, each catching what the others cannot:
//
//   - Sec-Fetch-Site. Every current browser sends it on every request; no SDK
//     sends it at all. "none" is a typed URL or a bookmark and "same-origin" is
//     this shim's own page, of which there is none — anything else is a page
//     somewhere else asking.
//   - Origin, refused by its presence rather than allowlisted. Browsers attach
//     it to every POST, form submissions included. This shim has no legitimate
//     browser client, so there is no origin to allow and no list to get wrong.
//   - The Host header. This is the only one that catches DNS rebinding, and
//     rebinding is the only attack the first two cannot see: a page at
//     http://evil.example:3000 whose name resolves to 127.0.0.1 is same-origin
//     with itself, so it sends Sec-Fetch-Site: same-origin and no Origin. What
//     it cannot change is the Host header, which comes from its own URL.
func (s *Server) refuseBrowser(r *http.Request) string {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return "cross-site request refused: this shim has no browser client (see docs/e2b-shim.md)"
	}
	if r.Header.Get("Origin") != "" {
		return "browser origins are not clients of this shim; the Origin header is refused by its presence"
	}
	if !s.hostAllowed(r.Host) {
		return "Host header does not name the address this shim bound to (" + s.Policy.Addr + ")"
	}
	return ""
}

// hostAllowed is the Host check, and it is deliberately not a string equality
// against the bound address alone.
//
// Equality is what host/view.go does, and it is right there because that server
// binds 127.0.0.1:0 itself and prints the only URL anyone will ever use. This
// one is reached through an address the operator chose — `--addr :3000` binds
// every interface, and `http://localhost:3000` is what a person types and what
// the E2B SDK's own E2B_DEBUG default is — so equality alone would refuse
// working setups the docs describe.
//
// What the check actually has to stop is a NAME, because DNS rebinding needs
// one: the attacker's page must be served from a name they control that later
// resolves to the loopback address. An IP literal in a Host header cannot have
// been rebound, and "localhost" is a name no attacker's DNS can answer for. So
// the rule is: the port must match what this shim bound, and the host part must
// be an IP literal or exactly "localhost". "kelyfos.localhost" and
// "127.0.0.1.nip.io" are names and are refused, which is the case a
// suffix-match would have got wrong.
//
// An empty Policy.Addr refuses everything. A Server that was never told what it
// bound to cannot answer this question, and a check that switches itself off
// when a field is unset is the shape of half the findings in this review.
// splitHostMaybePort splits a Host header that may carry no port at all.
//
// Both browsers and Go's own http.Client omit the port when it is the scheme's
// default, so `--addr 127.0.0.1:80` used to answer 403 to every request —
// net.SplitHostPort simply failed and the check refused. Fail-closed, so never
// a hole, but a shim that refuses its only client is an outage rather than a
// defence (P7-17/F2, second review round). This shim serves plain HTTP, so an
// absent port means 80 and nothing else.
//
// An empty host means the header could not be read at all, and the caller
// refuses.
func splitHostMaybePort(h string) (host, port string) {
	if h == "" {
		return "", ""
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		return host, port
	}
	// No colon at all, or a bare IPv6 literal in brackets with no port. Only
	// the first is a legal portless Host; a bracketed form without a port is
	// unbracketed here so ParseIP can still judge it.
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1], "80"
	}
	if strings.Contains(h, ":") {
		// A colon that SplitHostPort refused: a bare IPv6 literal without
		// brackets, or a malformed header. Neither is something to guess at.
		return "", ""
	}
	return h, "80"
}

func (s *Server) hostAllowed(h string) bool {
	if s.Policy.Addr == "" {
		return false
	}
	if h == s.Policy.Addr {
		return true
	}
	host, port := splitHostMaybePort(h)
	if host == "" {
		return false
	}
	_, boundPort, err := net.SplitHostPort(s.Policy.Addr)
	if err != nil || port != boundPort {
		return false
	}
	return net.ParseIP(host) != nil || strings.EqualFold(host, "localhost")
}

// Close stops every sandbox the shim created.
func (s *Server) Close() {
	s.mu.Lock()
	boxes := make([]*box, 0, len(s.boxes))
	for _, b := range s.boxes {
		boxes = append(boxes, b)
	}
	s.boxes = map[string]*box{}
	s.mu.Unlock()
	for _, b := range boxes {
		b.close("shutdown")
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

// --- control plane ---

type sandboxResponse struct {
	TemplateID  string `json:"templateID"`
	SandboxID   string `json:"sandboxID"`
	ClientID    string `json:"clientID"`
	EnvdVersion string `json:"envdVersion"`
}

// maxCreateBody bounds the JSON POST /sandboxes will read. The only field this
// route reads is a template id it echoes back and never honours, so anything
// past a few kilobytes is not a request this shim has a use for — and an
// unbounded decode on a route that boots a microVM is a second cost on top of
// the machine.
const maxCreateBody = 64 << 10

func (s *Server) createSandbox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TemplateID string `json:"templateID"`
	}
	// The decode error used to be discarded, so a body that was not JSON at
	// all — a cross-origin <form> POST, say — cost the host a microVM
	// (P7-17/F2). io.EOF is not that error: an absent body has always meant
	// "the defaults" for `curl -X POST /sandboxes`, and still does. Anything
	// after the first value is refused too, because a request with a JSON
	// object and then garbage is not a request any client of this shim makes.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCreateBody))
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest,
			"the request body is not JSON; POST /sandboxes takes {\"templateID\": \"...\"} or nothing at all")
		return
	}
	if dec.More() {
		writeErr(w, http.StatusBadRequest,
			"the request body carries more than one JSON value")
		return
	}

	// Before the machine is built rather than after, because the cost this is
	// bounding is the building of it.
	s.mu.Lock()
	live := len(s.boxes)
	s.mu.Unlock()
	if live >= MaxSandboxes {
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"this shim holds %d sandboxes and its limit is %d; delete one before asking for another",
			live, MaxSandboxes))
		return
	}

	b, err := s.boot(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Registration is the limit's enforcement point (register): the census
	// above released the lock before a multi-second boot, and a burst of
	// concurrent POSTs took the space while this machine was coming up. The
	// already-booted machine is torn down on a lost race — that cost is
	// bounded, because the loser is exactly one machine per racing request.
	// The close is load-bearing, not tidiness: a booted box that never enters
	// s.boxes is unreachable by GET/DELETE and by Close, an orphaned VMM the
	// cap never counts (found by the adversarial review of this fix — the
	// first version refused the request and walked away).
	if !s.register(b) {
		b.close("over_limit")
		writeErr(w, http.StatusTooManyRequests, fmt.Sprintf(
			"this shim's limit is %d sandboxes and it is full; delete one before asking for another",
			MaxSandboxes))
		return
	}

	template := req.TemplateID
	if template == "" {
		template = s.Policy.Flavor
	}
	sb := b.sb
	writeJSON(w, http.StatusCreated, sandboxResponse{
		TemplateID:  template,
		SandboxID:   sb.State.ID,
		ClientID:    "kelyfos",
		EnvdVersion: EnvdVersion,
	})
}

// boot brings up one sandbox under the project's policy, with its own flight
// recorder, its own egress path when the policy grants any, and its own cgroup
// slice when the policy caps CPU time.
//
// The order is the order `kelyfos run` uses and it is load-bearing: the TAP
// first, then the proxy bound on it, then the firewall that makes the proxy the
// only reachable destination, and only then a machine that can send a packet
// anywhere (docs/networking.md). Anything that fails part way unwinds what it
// already built rather than leaving a TAP behind.
// register installs one booted box, and is the moment MaxSandboxes is
// enforced (audit 2026-09-01, A9). It is a copy of the pattern host/servemcp's
// adopt has always used, for the reason that function's own comment gives:
// the census at the top of createSandbox releases the lock before a
// multi-second boot, so checking only there turns the cap into a race that a
// burst of concurrent POSTs wins. The watcher starts here rather than at the
// boot site, so the map entry and its watcher come into existence together
// and the watcher can never fire on a box the map does not hold (P7-17/A2).
func (s *Server) register(b *box) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.boxes) >= MaxSandboxes {
		return false
	}
	s.boxes[b.sb.State.ID] = b
	b.stopped = make(chan struct{})
	go s.watchRecorder(b.sb.State.ID, b)
	return true
}

func (s *Server) boot(parent context.Context) (*box, error) {
	id, err := sandbox.NewID()
	if err != nil {
		return nil, err
	}
	b := &box{}
	ok := false
	// The one teardown, not a copy of it. This defer used to hand-roll a strict
	// subset of close() — proxy, network, slice, recorder, and no machine — so a
	// failure after the VM was running left a microVM nothing could reach: it
	// never entered s.boxes, so `killSandbox` could not find it and the census
	// that bounds this shim under-counted it forever. The refusal that reaches
	// it is the guest's to make (finding M-1): InstallTrustAnchor fails when the
	// guest answers no.
	defer func() {
		if !ok {
			b.close("error")
		}
	}()

	opts := sandbox.Options{
		ID:           id,
		Arch:         s.Policy.Arch,
		Flavor:       s.Policy.Flavor,
		VcpuCount:    s.Policy.Vcpus,
		MemMiB:       s.Policy.MemMiB,
		IO:           s.Policy.IO,
		ScratchBytes: s.Policy.ScratchBytes,
		Quiet:        true,
	}
	if s.Policy.CPUQuota > 0 {
		if b.slice, err = sandbox.NewCPUSlice(id, s.Policy.CPUQuota); err != nil {
			return nil, err
		}
		opts.CPUSlice = b.slice
	}

	var ca *egress.CA
	if len(s.Policy.Allow) > 0 {
		opts.Allow = s.Policy.Allow
		if b.net, err = sandbox.NewNetwork(id); err != nil {
			return nil, err
		}
		opts.Net = b.net
		pol := egress.Policy{Allow: s.Policy.Allow, Secrets: s.Policy.Secrets}
		if len(pol.Secrets) > 0 {
			if ca, err = egress.NewCA(); err != nil {
				return nil, err
			}
		}
		b.proxy = &egress.Proxy{Policy: pol, CA: ca, Peer: b.net.GuestAddr()}
		port, err := b.proxy.Listen(b.net.HostIP.String() + ":0")
		if err != nil {
			return nil, err
		}
		if err := b.net.Restrict(port); err != nil {
			return nil, err
		}
		go b.proxy.Serve()
	}

	if b.sb, err = sandbox.New(opts); err != nil {
		return nil, err
	}

	// Opened before the VM starts and closed after it stops, so the record
	// brackets the thing it describes — the same contract every other entry
	// path holds to (docs/events.md).
	if b.rec, err = recorder.Open(sandbox.Root(), id); err != nil {
		return nil, err
	}
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionStart, Image: s.Policy.Flavor, Arch: s.Policy.Arch,
		Kelyfos: s.Policy.Version, Argv: s.Policy.Argv,
		Reason: "created through the E2B shim",
	})
	s.wireEgressAudit(b)

	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	if err := b.sb.Start(ctx); err != nil {
		_ = b.sb.Shutdown(2 * time.Second)
		return nil, err
	}
	ready, err := b.sb.WaitReady(ctx)
	if err != nil {
		_ = b.sb.Shutdown(2 * time.Second)
		return nil, err
	}
	if ca != nil {
		if err := b.sb.InstallTrustAnchor(ca.AnchorPEM()); err != nil {
			return nil, err
		}
	}
	overlay := ready.Overlay
	_ = b.rec.Append(recorder.Event{
		Type: recorder.TypeSessionReady, BootMS: b.sb.State.BootReadyMS,
		Kernel: ready.Kernel, Supervisor: ready.Supervisor, Overlay: &overlay,
	}.WithPosture(b.sb.State.Jailed, b.sb.State.Profile))

	// What this machine was permitted (P7-2, docs/policy-record.md §5).
	// Workspace, plugins, forwards, max_runtime and idle_timeout are all
	// genuinely absent from the E2B-compatible surface — docs/e2b-shim.md's
	// own "what it deliberately omits" — not values this task invented.
	rootfsSHA, kernelSHA := sessionpolicy.Digests(sandbox.ImageDir(s.Policy.Arch))
	_ = b.rec.Append(recorder.NewSessionPolicy("", recorder.PolicyFields{
		VcpuCount: s.Policy.Vcpus, MemMiB: s.Policy.MemMiB, CPUQuota: s.Policy.CPUQuota,
		ScratchBytes: s.Policy.ScratchBytes,
		NetMbpsRx:    s.Policy.IO.NetMbpsRx, NetMbpsTx: s.Policy.IO.NetMbpsTx,
		DiskIOPS: s.Policy.IO.DiskIOPS, DiskMbps: s.Policy.IO.DiskMbps,
		Allow: s.Policy.Allow, Ports: sessionpolicy.Ports(s.Policy.Allow),
		Secrets:      sessionpolicy.Secrets(s.Policy.Secrets),
		Tools:        sessionpolicy.ToolsForCLI(false),
		RootfsSHA256: rootfsSHA,
		KernelSHA256: kernelSHA,
	}))

	// Synchronously, before this box is handed back to be registered
	// (P7-17/A2, review round). The three appends above discard their errors
	// like every other Append in this product, so any of them — and every
	// wireEgressAudit callback the machine has already made — can latch the
	// recorder while the boot is still running.
	//
	// The first version of this started the watcher HERE, at recorder.Open,
	// reasoning that it should cover the recorder's whole life. The review
	// found what that costs: the watcher fires before createSandbox has put the
	// box in s.boxes, so `delete` removes nothing, `b.close` shuts the microVM
	// down, and boot then returns (b, nil) to a caller that answers 201 and
	// registers a corpse — occupying one of MaxSandboxes for the life of the
	// process, listed by GET /sandboxes, and handed out by only() to every
	// envd file call. It could also run b.close CONCURRENTLY with Start and
	// WaitReady, which share no lock.
	//
	// A check is the right shape for the window before registration and a
	// watcher is the right shape for after it: this one cannot race anything,
	// because nothing else holds this box yet. The watcher now starts where the
	// box is registered, which is the single point serve-mcp's adopt uses for
	// exactly this reason.
	if seq, ferr := b.rec.Failure(); ferr != nil {
		return nil, fmt.Errorf("the flight recorder for this sandbox stopped at event %d "+
			"before it finished booting (%v), so it was not started: a sandbox nobody is "+
			"recording is not one this shim runs", seq, ferr)
	}
	ok = true
	return b, nil
}

// wireEgressAudit points the proxy's reports at this sandbox's chain. Every
// connection attempt is recorded, allowed or blocked, and a bound credential is
// recorded by name — never by value (docs/events.md §4).
func (s *Server) wireEgressAudit(b *box) {
	if b.proxy == nil {
		return
	}
	b.proxy.OnSecret = func(name, host string) {
		_ = b.rec.Append(recorder.Event{Type: recorder.TypeSecretUse, Name: name, Host: host})
	}
	b.proxy.OnWithheld = func(name, host, reason string) {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSecretWithheld, Name: name, Host: host, Reason: reason,
		})
	}
	b.proxy.OnScrubbed = func(name, host string) {
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeSecretScrubbed, Name: name, Host: host,
		})
	}
	b.proxy.OnEvent = func(a egress.Attempt) {
		allowed := a.Allowed
		_ = b.rec.Append(recorder.Event{
			Type: recorder.TypeEgressAttempt, Host: a.Host, Port: a.Port,
			Allowed: &allowed, Reason: a.Reason, Mode: a.Mode,
			// What went wrong, for the operator, when Reason is a category
			// rather than an explanation (P7-17/C, review round). Redacted by
			// an erasure like every other free-text field.
			Error:   shimAttemptError(a),
			BytesIn: a.BytesIn, BytesOut: a.BytesOut,
			// This is wireProxyAudit's twin, and it has to carry every field
			// wireProxyAudit carries. It did not carry Peer, so a foreign-peer
			// refusal on the E2B path recorded with no peer, no host and no
			// port — an event that says a connection was refused and nothing
			// whatever about which one (F9).
			Peer: a.Peer,
			// See wireProxyAudit: the resolved address is recorder-only (F14).
			ResolvedAddr: a.ResolvedAddr,
		})
	}
}

func (s *Server) listSandboxes(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sandboxResponse, 0, len(s.boxes))
	for id := range s.boxes {
		out = append(out, sandboxResponse{
			TemplateID: s.Policy.Flavor, SandboxID: id, ClientID: "kelyfos", EnvdVersion: EnvdVersion,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) killSandbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.mu.Lock()
	sb, ok := s.boxes[id]
	delete(s.boxes, id)
	why := s.lostReason(id)
	s.mu.Unlock()
	if !ok {
		if why != "" {
			writeErr(w, http.StatusNotFound, "sandbox "+id+" is gone: "+why)
			return
		}
		writeErr(w, http.StatusNotFound, "no sandbox "+id+" created by this shim")
		return
	}
	sb.close("shutdown")
	w.WriteHeader(http.StatusNoContent)
}

// --- envd files ---

// only returns the single sandbox to act on. The SDK addresses envd by URL
// rather than by id, and the shim serves one address, so a single running
// sandbox is unambiguous and several are not.
func (s *Server) only() (*box, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch len(s.boxes) {
	case 0:
		if len(s.lost) > 0 {
			for id, why := range s.lost {
				return nil, fmt.Errorf("the sandbox this shim was serving (%s) is gone: %s",
					id, why)
			}
		}
		return nil, fmt.Errorf("no sandbox has been created through this shim")
	case 1:
		for _, b := range s.boxes {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%d sandboxes are running; the E2B shim addresses envd by URL and "+
		"cannot tell them apart — create one at a time", len(s.boxes))
}

func (s *Server) readFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}
	sb, err := s.only()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// base64 keeps the round trip binary-safe over a channel that carries text.
	res, err := sandbox.Exec(sb.sb.State.UDSPath,
		[]string{"/bin/sh", "-c", "base64 " + shellQuote(path)}, nil, 30*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Code != 0 {
		writeErr(w, http.StatusNotFound, strings.TrimSpace(string(res.Stderr)))
		return
	}
	data, err := decodeBase64Lines(res.Stdout)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) writeFile(w http.ResponseWriter, r *http.Request) {
	sb, err := s.only()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	path := r.URL.Query().Get("path")

	var body []byte
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "multipart/") {
		name, data, err := firstMultipartFile(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		body = data
		if path == "" {
			path = name
		}
	} else {
		body, err = io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}

	script := "mkdir -p \"$(dirname " + shellQuote(path) + ")\" && base64 -d > " + shellQuote(path)
	res, err := sandbox.Exec(sb.sb.State.UDSPath, []string{"/bin/sh", "-c", script},
		[]byte(encodeBase64(body)), 60*time.Second)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Code != 0 {
		writeErr(w, http.StatusInternalServerError, strings.TrimSpace(string(res.Stderr)))
		return
	}
	// A file that arrived through this door is recorded exactly as one that
	// arrived through an MCP tool: by path, size and digest, never by content
	// (docs/events.md §4). Reads are not recorded here for the same reason they
	// are not recorded there — the record is of what was changed.
	sum := sha256.Sum256(body)
	_ = sb.rec.Append(recorder.Event{
		Type: recorder.TypeFileWrite, Path: path, Bytes: len(body),
		SHA256: hex.EncodeToString(sum[:]), Via: "shim",
	})
	writeJSON(w, http.StatusOK, []map[string]any{{"name": path, "path": path, "type": "file"}})
}

// notImplemented answers the parts of E2B's surface the shim does not cover —
// principally command execution, which the current SDK performs over Connect RPC
// with protobuf streaming. Saying so plainly beats a 404 that looks like a bug.
func (s *Server) notImplemented(w http.ResponseWriter, r *http.Request) {
	writeErr(w, http.StatusNotImplemented, fmt.Sprintf(
		"the KelyfOS E2B shim is a best-effort subset and does not implement %s %s. "+
			"Sandbox lifecycle and file transfer are supported; command execution uses Connect RPC "+
			"in the E2B SDK and is not. Use the MCP interface (kelyfos mcp) for commands. "+
			"See docs/e2b-shim.md", r.Method, r.URL.Path))
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"code": code, "message": msg})
}

func firstMultipartFile(r *http.Request) (string, []byte, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return "", nil, err
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return "", nil, fmt.Errorf("multipart body carried no file")
		}
		if err != nil {
			return "", nil, err
		}
		if part.FileName() == "" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(part, 64<<20))
		return part.FileName(), data, err
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func encodeBase64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// decodeBase64Lines joins the wrapped output of base64(1) before decoding.
func decodeBase64Lines(out []byte) ([]byte, error) {
	joined := strings.Join(strings.Fields(string(out)), "")
	return base64.StdEncoding.DecodeString(joined)
}

// shimAttemptError is host/denials.go's attemptError, in this package.
//
// Duplicated rather than exported, deliberately and in the shape this
// repository already uses for the twin of wireProxyAudit that lives here: the
// two audit wirings are the same six lines in two packages, and the review that
// found this one missing found it by looking for exactly that pair (F9's second
// round). A shared helper would be one import from internal/egress to a host
// concern; the duplication is four lines and is pinned by the mapping test.
func shimAttemptError(a egress.Attempt) *recorder.EvError {
	if a.Detail == "" {
		return nil
	}
	return &recorder.EvError{Kind: "io", Message: proto.SafeText(a.Detail)}
}
