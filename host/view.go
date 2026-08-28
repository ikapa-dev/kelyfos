// kelyfos view (P7-12) is the one place in this codebase that opens a
// listening socket — D60 admits it, narrowly, as a localhost-only, read-only,
// live viewer for a single session, and every condition D60 and the task
// text attach to that admission is enforced here structurally rather than by
// convention: loopback-only with no relaxing flag, a per-process token
// required and constant-time-compared on every route, a Host-header check
// against DNS rebinding, GET/HEAD only, a hash-pinned CSP, and a client
// script that never touches innerHTML. docs/view.md is the reader-facing
// half of this file; read it alongside the doc comments below.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/p4r4n0rm4l/KelyfOS/internal/digest"
	"github.com/p4r4n0rm4l/KelyfOS/internal/proto"
	"github.com/p4r4n0rm4l/KelyfOS/internal/recorder"
	"github.com/p4r4n0rm4l/KelyfOS/internal/report"
	"github.com/p4r4n0rm4l/KelyfOS/internal/sandbox"
)

// defaultViewIdleTimeout is the one adjustable knob P7-12 permits (a flag,
// per the task text) — everything else (bind address, token requirement,
// method allowlist, Host check) has none, on purpose.
const defaultViewIdleTimeout = 30 * time.Minute

func viewCmd(argv []string) error {
	fs := flag.NewFlagSet("kelyfos view", flag.ExitOnError)
	id := fs.String("session", "", "session id (default: the most recent)")
	idleTimeout := fs.Duration("idle-timeout", defaultViewIdleTimeout,
		"exit after this long with nobody connected and nothing new recorded")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `usage: kelyfos view [flags]

Serves the same report "kelyfos log --export" builds — the run map, the
agent sheets, the reach matrix, the store panel and the timeline — live,
over HTTP, with new events pushed to an open tab as the session continues.

This is the one place KelyfOS opens a listening socket (D60). Every
condition that comes with that exception is structural, not a default that
can be relaxed: it binds 127.0.0.1 on a kernel-assigned port and refuses
any other address, with no flag that changes it; it mints a 256-bit token
for this process only, prints it once below as part of the URL, and
requires it — compared in constant time — on every route including the
live-update stream; it checks the Host header on every request against the
address it actually bound (the standard defence against DNS rebinding); it
answers GET and HEAD only, so nothing on any page can change a sandbox; its
Content-Security-Policy is enforced by a header, its one inline script's
hash is pinned by a test, and that script only ever writes plain text into
the page. The flight recorder is opened read-only.

kelyfos view never starts on its own — nothing else runs it for you — and it
never opens a browser; it prints the URL and stops there. It exits on its
own once the session ends, after --idle-timeout with nobody watching and
nothing to report, or on Ctrl-C.

The residual risk docs/view.md states plainly: loopback is reachable by
every local user on a shared host, so the token is what actually keeps them
out, not the address.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *idleTimeout <= 0 {
		return fmt.Errorf("--idle-timeout must be positive, got %s", *idleTimeout)
	}

	sessionID, err := resolveSession(*id)
	if err != nil {
		return err
	}
	path := recorder.Path(sandbox.Root(), sessionID)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no flight recorder for session %s: %w", sessionID, err)
	}

	// The same Ctrl-C wiring every other long-running kelyfos command uses
	// (team up, run, serve-mcp, fork, snapshot restore, log --refresh).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runView(ctx, sessionID, path, *idleTimeout, os.Stdout)
}

// bindLoopback is D60's "no flag relaxes this" made structural rather than
// documented: it takes no argument, so nothing anywhere in this process —
// no flag, no config key, no environment variable — has anywhere to hand it
// a different address. TestBindLoopbackTakesNoArguments asserts the zero
// parameter count by reflection; TestBindLoopbackBindsLoopbackOnly asserts
// what it actually binds.
func bindLoopback() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

// newViewToken mints P7-12's whole authentication story: 256 bits from
// crypto/rand, hex-encoded, once per process. It is never a CLI argument —
// see runView's own doc comment for how it reaches the browser instead.
func newViewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// viewPollInterval is how often the background loop re-reads the session's
// flight recorder for new events or session.end. A var, not a const, only so
// the test suite can shrink it — there is deliberately no flag for it: the
// task text makes --idle-timeout the one adjustable knob and nothing else.
var viewPollInterval = time.Second

// runView is the whole server: minting the token, binding the listener,
// wiring the routes, printing the URL once, and blocking until the session
// ends, the idle timeout fires, or ctx is cancelled (Ctrl-C).
//
// How the token reaches the browser: it is baked into the printed URL as a
// query parameter (?token=…), the same pattern Jupyter and code-server use
// for exactly this problem — a secret that must reach a browser a process
// never launches, without ever becoming a CLI argument (shell history, ps)
// or an environment variable a browser cannot read. The client's own script
// forwards it onto the SSE request the same way. curl callers who would
// rather keep it out of a URL (logs, shell history of the *curl* command)
// can send `Authorization: Bearer <token>` instead; both are accepted,
// compared in constant time, on every route. docs/view.md states the
// residual honestly: a URL carrying a token can end up in browser history
// or a Referer header if the page ever linked offsite, which this page
// never does (default-src 'none') — but the caveat is about the mechanism,
// not about this page's own behaviour, so it is stated rather than hidden.
func runView(ctx context.Context, sessionID, path string, idleTimeout time.Duration, out io.Writer) error {
	token, err := newViewToken()
	if err != nil {
		return fmt.Errorf("minting a viewer token: %w", err)
	}

	ln, err := bindLoopback()
	if err != nil {
		return fmt.Errorf("binding the viewer: %w", err)
	}
	defer ln.Close()

	v := newViewServer(sessionID, path, token, ln.Addr().String())

	// wrap has to sit outside the mux, not inside it on each pattern:
	// http.ServeMux.ServeHTTP runs its own path-cleaning redirect (double
	// slashes, "." and ".." segments) *before* dispatching to any registered
	// handler, so a per-pattern wrap never sees a "dirty" request at all —
	// it answers with none of the method, Host or token checks applied. This
	// was found live: an unauthenticated, wrong-Host, POST request to "//"
	// or "//events" got a 307 with none of wrap's headers set. Wrapping the
	// mux itself means every request, dirty path included, clears all three
	// checks before ServeMux ever runs its own redirect logic.
	mux := http.NewServeMux()
	mux.HandleFunc("/", v.handleIndex)
	mux.HandleFunc("/events", v.handleEvents)
	srv := &http.Server{Handler: v.wrap(mux.ServeHTTP)}

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Serve(ln) }()

	url := fmt.Sprintf("http://%s/?token=%s", v.host, token)
	fmt.Fprintf(out, "kelyfos view: %s\n", url)
	fmt.Fprintln(out, "  loopback only · token required on every route · GET/HEAD only — docs/view.md")
	fmt.Fprintf(out, "  exits when session %s ends, after %s idle, or on Ctrl-C\n", sessionID, idleTimeout)

	shutdownReason := make(chan string, 1)
	go v.poll(ctx, idleTimeout, shutdownReason)

	var reason string
	select {
	case <-ctx.Done():
		reason = "interrupted"
	case reason = <-shutdownReason:
	case serr := <-serverErr:
		if serr != nil && serr != http.ErrServerClosed {
			return serr
		}
		reason = "server stopped"
	}

	fmt.Fprintf(out, "kelyfos view: stopping (%s)\n", reason)
	// Close every open SSE stream's channel *before* Shutdown: Shutdown waits
	// for active handlers to return on their own, and a handler blocked on
	// <-ch never will until this runs — ordering it the other way around
	// would just spend the whole grace period waiting on itself.
	v.closeAllClients()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	return nil
}

// sseFrame is one Server-Sent Event: an event name and a JSON-encoded data
// line. json.Marshal escapes every control byte and every `<`, `>`, `&`
// inside a string value (Go's default HTML-escaping), so whatever hostile
// content a guest chose for a command, a path or an agent name arrives on
// the wire as an ordinary, single-line, fully-escaped JSON string — never as
// a raw newline that could break SSE's own line-oriented framing, and never
// as bytes a naive consumer could mistake for markup.
type sseFrame struct {
	event string
	data  []byte
}

// viewServer holds the one session's live state: what the background poller
// last saw, and the set of currently-connected SSE clients to broadcast to.
type viewServer struct {
	sessionID string
	path      string
	token     string
	// host is the address bindLoopback actually bound, formatted exactly as
	// net.Listener.Addr().String() renders it ("127.0.0.1:PORT") — the value
	// every request's Host header must match.
	host string

	mu           sync.Mutex
	clients      map[chan sseFrame]struct{}
	lastCount    int
	ended        bool
	lastActivity time.Time
}

func newViewServer(sessionID, path, token, host string) *viewServer {
	return &viewServer{
		sessionID:    sessionID,
		path:         path,
		token:        token,
		host:         host,
		clients:      map[chan sseFrame]struct{}{},
		lastActivity: time.Now(),
	}
}

// wrap is every binding condition that applies to every route, applied once
// rather than per-handler: the method allowlist that makes "read-only"
// structural instead of a promise, the Host check that defeats DNS
// rebinding, and the constant-time token check. Only a request that clears
// all three reaches a handler or resets the idle clock.
func (v *viewServer) wrap(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", viewCSP())

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "kelyfos view answers GET and HEAD only — it is a reader, not a control surface", http.StatusMethodNotAllowed)
			return
		}
		if r.Host != v.host {
			http.Error(w, "Host header does not match the address kelyfos view bound to", http.StatusForbidden)
			return
		}
		if !v.tokenOK(r) {
			http.Error(w, "missing or wrong token", http.StatusUnauthorized)
			return
		}
		v.touch()
		h(w, r)
	}
}

// tokenOK accepts the token either as ?token= (what the printed URL carries,
// and what a browser navigating or opening an EventSource can send) or as an
// Authorization: Bearer header (a way for curl and similar to authenticate
// without putting the token in a URL at all). Either way the comparison is
// constant-time — crypto/subtle, never == or strings.Compare — per D60.
func (v *viewServer) tokenOK(r *http.Request) bool {
	got := r.URL.Query().Get("token")
	if got == "" {
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			got = strings.TrimPrefix(ah, "Bearer ")
		}
	}
	if got == "" {
		return false
	}
	// ConstantTimeCompare requires equal-length inputs to say anything about
	// their content in constant time; comparing the length first leaks
	// nothing secret (token length is fixed and public — the string it
	// mints is always 64 hex characters) and avoids the panic-free but
	// meaningless comparison ConstantTimeCompare would otherwise report as
	// "unequal" instantly, for the wrong reason, if lengths already differ.
	if len(got) != len(v.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(v.token)) == 1
}

func (v *viewServer) touch() {
	v.mu.Lock()
	v.lastActivity = time.Now()
	v.mu.Unlock()
}

func (v *viewServer) idleFor() time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	return time.Since(v.lastActivity)
}

func (v *viewServer) addClient(ch chan sseFrame) {
	v.mu.Lock()
	v.clients[ch] = struct{}{}
	v.mu.Unlock()
	v.touch()
}

func (v *viewServer) removeClient(ch chan sseFrame) {
	v.mu.Lock()
	delete(v.clients, ch)
	v.mu.Unlock()
}

func (v *viewServer) noClients() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.clients) == 0
}

func (v *viewServer) closeAllClients() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for ch := range v.clients {
		close(ch)
		delete(v.clients, ch)
	}
}

// broadcast fans one frame out to every connected client. A slow or wedged
// client's buffered channel filling up drops that one update for that one
// client rather than blocking every other connected tab, or the poller
// itself, on it.
func (v *viewServer) broadcast(f sseFrame) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for ch := range v.clients {
		select {
		case ch <- f:
		default:
		}
	}
}

// handleIndex renders exactly what internal/report already renders for
// `kelyfos log --export` — the run map, agent sheets, reach matrix, store
// panel and timeline, from whatever the flight recorder holds right now —
// and adds only this task's own live-update wiring on top (injectLive).
// The file is opened read-only by os.ReadFile (which opens O_RDONLY); no
// write handle to the flight recorder exists anywhere in this command.
func (v *viewServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	// http.ServeMux treats a bare "/" pattern as a catch-all for any path
	// with no more specific match, so without this an arbitrary path would
	// silently render the same report instead of a 404. Harmless either way
	// — nothing here ever reads r.URL.Path — but a real 404 is the honest
	// answer for a path that names nothing, and it is what a reviewer
	// scanning routes for "does a URL fragment reach the filesystem" should
	// find: nowhere, not even here.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	blob, err := os.ReadFile(v.path)
	if err != nil {
		http.Error(w, "no flight recorder for this session", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if _, err := report.Render(&buf, v.sessionID, blob); err != nil {
		http.Error(w, "rendering the report failed", http.StatusInternalServerError)
		return
	}
	page, err := injectLive(buf.Bytes())
	if err != nil {
		// A change to internal/report/template.go moved or reworded the one
		// anchor this function depends on. Failing loudly here — rather than
		// silently serving a page with the wrong CSP, or no live section at
		// all — is the point of asserting "exactly once" in injectLive.
		http.Error(w, fmt.Sprintf("assembling the live page failed: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(page)
}

// handleEvents is the SSE stream. It carries data, never markup: every
// message is one JSON object, described in viewScript's own comment, and
// nothing server-side ever writes an HTML tag into it — safety here rests on
// the client only ever placing that data with textContent, not on this
// handler escaping anything for HTML purposes.
func (v *viewServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	flusher.Flush()

	ch := make(chan sseFrame, 32)
	v.addClient(ch)
	defer v.removeClient(ch)

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case frame, open := <-ch:
			if !open {
				return
			}
			writeSSE(w, frame)
			flusher.Flush()
		}
	}
}

func writeSSE(w io.Writer, f sseFrame) {
	if f.event != "" {
		fmt.Fprintf(w, "event: %s\n", f.event)
	}
	fmt.Fprintf(w, "data: %s\n\n", f.data)
}

// poll is the one background loop that ever reads the flight recorder for
// the live view: it re-reads the file on a clock (the same "poll a growing
// file" shape host/log.go's own --refresh loop uses), notices new events or
// session.end, and tells runView's own select loop when to stop — on
// session.end immediately, or once idleFor() has passed idleTimeout with no
// client connected.
func (v *viewServer) poll(ctx context.Context, idleTimeout time.Duration, done chan<- string) {
	ticker := time.NewTicker(viewPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if v.tick() {
				done <- "the session ended"
				return
			}
			if v.noClients() && v.idleFor() > idleTimeout {
				done <- fmt.Sprintf("idle for more than %s with nobody connected", idleTimeout)
				return
			}
		}
	}
}

// tick re-reads the flight recorder once. It reports whatever new events
// arrived since the last tick to every connected client, and reports
// session.end exactly once, the moment it first sees it.
func (v *viewServer) tick() (ended bool) {
	blob, err := os.ReadFile(v.path)
	if err != nil {
		// Same tolerance host/log.go's refresh loop has for a transient
		// read: not fatal, retried on the next tick.
		return false
	}
	parsed, err := recorder.Read(bytes.NewReader(blob))
	if err != nil {
		return false
	}

	v.mu.Lock()
	prevCount := v.lastCount
	alreadyEnded := v.ended
	v.mu.Unlock()
	if alreadyEnded {
		return true
	}
	if len(parsed) < prevCount {
		// The record shrank — not a shape this loop's caller should ever
		// see against a live session (nothing rewrites a running session's
		// own file smaller), but treating it as "nothing new" rather than
		// panicking on a negative slice bound is the safe reading.
		return false
	}

	if len(parsed) > prevCount {
		newEvents := parsed[prevCount:]
		lines := make([]string, 0, len(newEvents))
		for _, e := range newEvents {
			lines = append(lines, viewLogLine(e))
		}
		_, head, _ := recorder.Verify(bytes.NewReader(blob))
		v.mu.Lock()
		v.lastCount = len(parsed)
		v.mu.Unlock()

		payload, _ := json.Marshal(struct {
			Count int      `json:"count"`
			Head  string   `json:"head"`
			Lines []string `json:"lines"`
		}{len(parsed), head, lines})
		v.broadcast(sseFrame{event: "update", data: payload})
	}

	d := digest.Walk(parsed)
	if d.Ended == "" {
		return false
	}
	v.mu.Lock()
	v.ended = true
	v.mu.Unlock()
	payload, _ := json.Marshal(struct {
		Count  int    `json:"count"`
		Reason string `json:"reason"`
	}{len(parsed), proto.SafeText(d.EndReason)})
	v.broadcast(sseFrame{event: "end", data: payload})
	return true
}

// viewLogLine renders one event as a single line of readable text for the
// live feed — a smaller, live-feed-scoped cousin of host/log.go's own
// printEvent, covering the events most worth surfacing as they happen
// rather than every one of them. It is a supplementary view, not the
// authoritative one: the authoritative record is the chain itself, which
// `kelyfos log` replays exactly. Every guest-influenced field goes through
// proto.SafeText, the same control-byte defence host/log.go's printEvent
// already applies to e.Reason — worth repeating here because this line is
// also a candidate for landing in someone's terminal if they curl /events
// directly instead of opening a browser.
func viewLogLine(e recorder.Event) string {
	ts := e.TS
	if len(ts) > 23 {
		ts = ts[11:23]
	}
	who := ""
	if e.Agent != "" {
		who = "[" + proto.SafeText(e.Agent) + "] "
	}
	switch e.Type {
	case recorder.TypeSessionStart:
		return fmt.Sprintf("%s  session start", ts)
	case recorder.TypeSessionReady:
		return fmt.Sprintf("%s  %sready (%d ms)", ts, who, e.BootMS)
	case recorder.TypeSessionEnd:
		return fmt.Sprintf("%s  session end: %s", ts, proto.SafeText(e.Reason))
	case recorder.TypeCommandStart:
		return fmt.Sprintf("%s  %s$ %s", ts, who, proto.SafeText(strings.Join(e.Cmd, " ")))
	case recorder.TypeCommandExit:
		code := -1
		if e.Code != nil {
			code = *e.Code
		}
		return fmt.Sprintf("%s  %sexit %d (%d ms)", ts, who, code, e.DurationMS)
	case recorder.TypeFileWrite:
		return fmt.Sprintf("%s  %swrite %s (%d bytes)", ts, who, proto.SafeText(e.Path), e.Bytes)
	case recorder.TypeEgressAttempt:
		verdict := "BLOCKED"
		if e.Allowed != nil && *e.Allowed {
			verdict = "allowed"
		}
		return fmt.Sprintf("%s  %segress %s %s:%d", ts, who, verdict, proto.SafeText(e.Host), e.Port)
	case recorder.TypeSecretUse:
		return fmt.Sprintf("%s  %ssecret %s -> %s", ts, who, proto.SafeText(e.Name), proto.SafeText(e.Host))
	case recorder.TypeTeamMessage, recorder.TypeTeamRefused:
		verb := "->"
		if e.Kind == "reply" {
			verb = "<-"
		}
		refused := ""
		if e.Type == recorder.TypeTeamRefused {
			refused = "REFUSED "
		}
		return fmt.Sprintf("%s  team %s%s %s %s", ts, refused, proto.SafeText(e.Agent), verb, proto.SafeText(e.Peer))
	case recorder.TypeTeamSpawn:
		if e.Outcome == "refused" {
			return fmt.Sprintf("%s  team REFUSED spawn by %s (%s)", ts, proto.SafeText(e.Agent), proto.SafeText(e.Reason))
		}
		return fmt.Sprintf("%s  team %s %s by %s", ts, proto.SafeText(e.Kind), proto.SafeText(e.Peer), proto.SafeText(e.Agent))
	case recorder.TypeResourceOOM:
		return fmt.Sprintf("%s  %sOOM-killed %s", ts, who, proto.SafeText(e.Comm))
	case recorder.TypeResourceTimeout:
		return fmt.Sprintf("%s  %stimed out on %s", ts, who, proto.SafeText(e.Budget))
	case recorder.TypeResourceSummary:
		return fmt.Sprintf("%s  %susage receipt: %.2f CPU-seconds", ts, who, e.CPUSeconds)
	default:
		return fmt.Sprintf("%s  %s%s", ts, who, e.Type)
	}
}

// --- the live page: injecting P7-12's own script into P7-8's report ---

// staticCSPMeta is internal/report/template.go's own CSP meta tag, copied
// here verbatim on purpose: the exported report genuinely carries no
// script ("still one file, still no scripts" — P7-8), so its
// default-src 'none' is correct for that page and wrong for this one, which
// does carry a script. injectLive removes it — asserting it was there
// exactly once — because a meta CSP and a header CSP both apply and combine
// restrictively; leaving default-src 'none' in place would block this
// page's script regardless of what the header below allows. This live page
// carries its policy in the Content-Security-Policy header only, which is
// also the more robust place for it to live.
const staticCSPMeta = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">`

const bodyClose = `</body></html>`

// liveSection is static markup this package authors, never built from
// guest- or session-influenced data, so it is safe to splice in as raw
// bytes the same way the rest of reportHTML is. Its inline style="" values
// reference the report's own CSS custom properties (--mono, --muted,
// --line), the identical pattern the report template already uses in
// several places (e.g. template.go's `style="color:var(--muted)"`), and sit
// under the same style-src 'unsafe-inline' the exported report already
// relies on — no new inline <style> element, so no second hash to pin.
const liveSection = `<section id="kelyfos-live" aria-live="polite" style="margin-top:36px;border-top:1px solid var(--line);padding-top:16px">
<h2>Live</h2>
<div id="kelyfos-live-status" style="color:var(--muted);font-size:12.5px;margin-bottom:8px">connecting&hellip;</div>
<div id="kelyfos-live-log" style="max-height:340px;overflow:auto;background:#0c1117;border:1px solid #26313f;border-radius:4px;padding:8px 10px;font-family:var(--mono);font-size:12.5px;line-height:1.6"></div>
</section>`

// viewScript is the one inline script this whole task adds. Its literal
// bytes are what viewScriptHash pins into the CSP header and what
// TestCSPHashMatchesServedScript independently recomputes from a live
// request, so the two cannot silently drift apart.
//
// What it is allowed to do, and no more (D60 / the task's RENDER-surface
// condition): read the token out of its own page's URL and forward it onto
// the EventSource request; parse each SSE message as JSON; write the
// decoded values into the page with .textContent only (never .innerHTML,
// .outerHTML, insertAdjacentHTML or document.write — none of those
// appear anywhere below, which is what makes "the live update carries data,
// never markup" a property of this file rather than a promise about it);
// build new DOM nodes with document.createElement/appendChild, which is
// structural DOM construction rather than writing markup; and, on
// session.end, update a status line — never a page reload, never a
// navigation the binding conditions did not ask for.
const viewScript = `(function(){
"use strict";
var params = new URLSearchParams(window.location.search);
var token = params.get("token") || "";
var log = document.getElementById("kelyfos-live-log");
var status = document.getElementById("kelyfos-live-status");
var countEl = document.getElementById("kelyfos-events");
var headEl = document.getElementById("kelyfos-head");
function setStatus(text) {
  if (status) { status.textContent = text; }
}
function addLine(text) {
  if (!log) { return; }
  var row = document.createElement("div");
  row.textContent = text;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}
if (!window.EventSource) {
  setStatus("this browser has no EventSource; reload the page to see a newer export");
} else {
  var src = new EventSource("/events?token=" + encodeURIComponent(token));
  src.addEventListener("update", function (ev) {
    try {
      var msg = JSON.parse(ev.data);
      if (typeof msg.count === "number" && countEl) { countEl.textContent = String(msg.count); }
      if (typeof msg.head === "string" && headEl) { headEl.textContent = msg.head; }
      if (Array.isArray(msg.lines)) {
        for (var i = 0; i < msg.lines.length; i++) { addLine(String(msg.lines[i])); }
      }
      setStatus("watching — " + msg.count + " event(s) so far");
    } catch (e) {}
  });
  src.addEventListener("end", function (ev) {
    var extra = "";
    try {
      var msg = JSON.parse(ev.data);
      extra = " (" + String(msg.reason || "") + ", " + String(msg.count) + " event(s) total)";
    } catch (e) {}
    setStatus("session ended" + extra + " — nothing more will arrive; the viewer process has exited");
    src.close();
  });
  src.onerror = function () { setStatus("live connection lost — the viewer process may have exited"); };
  setStatus("watching for updates…");
}
})();`

// viewScriptHash is 'sha256-<base64>' for viewScript's exact bytes,
// computed once, so the CSP header and the served script can never disagree
// about what they each claim the other is.
var viewScriptHash = "sha256-" + func() string {
	sum := sha256.Sum256([]byte(viewScript))
	return base64.StdEncoding.EncodeToString(sum[:])
}()

// viewCSP is the only Content-Security-Policy this page ships (the static
// report's own meta CSP is removed by injectLive). default-src 'none' as
// the floor, the same as the exported report; script-src names exactly
// viewScript's hash and nothing else — no 'unsafe-inline', no host source;
// style-src keeps the exported report's own 'unsafe-inline' (for its large
// pre-existing <style> block, unchanged by this task, plus this task's own
// style="" attributes); connect-src 'self' is what actually allows
// EventSource to reach /events under a default-src of 'none'; base-uri,
// form-action and frame-ancestors are all 'none' — there is no form on this
// page and it must never be framed.
func viewCSP() string {
	return "default-src 'none'; script-src '" + viewScriptHash + "'; " +
		"style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; " +
		"form-action 'none'; frame-ancestors 'none'"
}

// injectLive turns internal/report's static export page into this task's
// live one: the static CSP meta tag removed (viewCSP, sent as a header,
// replaces it) and the live section plus viewScript spliced in just before
// </body>. Both anchors are asserted present exactly once — a template.go
// change that moves or rewords either one fails this loudly (handleIndex
// turns the error into a 500) rather than silently serving a page with the
// wrong policy or no live wiring at all.
func injectLive(page []byte) ([]byte, error) {
	if n := bytes.Count(page, []byte(staticCSPMeta)); n != 1 {
		return nil, fmt.Errorf("internal/report's CSP meta tag found %d time(s), want exactly 1 — template.go changed under host/view.go", n)
	}
	page = bytes.Replace(page, []byte(staticCSPMeta), nil, 1)

	if n := bytes.Count(page, []byte(bodyClose)); n != 1 {
		return nil, fmt.Errorf("internal/report's closing %q found %d time(s), want exactly 1 — template.go changed under host/view.go", bodyClose, n)
	}
	suffix := liveSection + "<script>" + viewScript + "</script>" + bodyClose
	page = bytes.Replace(page, []byte(bodyClose), []byte(suffix), 1)
	return page, nil
}
