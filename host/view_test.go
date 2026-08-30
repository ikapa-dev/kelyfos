package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

// These tests exercise host/view.go (P7-12) against the binding conditions
// in P7-12 (docs/roadmap.md) and D60: loopback-only, token required in
// constant time on every route including the SSE stream, a Host check that
// defeats DNS rebinding, GET/HEAD only structurally, a hash-pinned CSP, and
// an SSE payload that reaches the client as inert data even when the
// session itself contains hostile strings.

// --- D60's own bind-address guarantee: structural, not a check ---

func TestBindLoopbackTakesNoArguments(t *testing.T) {
	fn := reflect.ValueOf(bindLoopback)
	if fn.Type().NumIn() != 0 {
		t.Fatalf("bindLoopback takes %d argument(s); D60 requires the bind address to have nowhere in the process it could be handed in from, and a parameter is exactly such a place", fn.Type().NumIn())
	}
}

func TestBindLoopbackBindsLoopbackOnlyOnAKernelAssignedPort(t *testing.T) {
	ln, err := bindLoopback()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("bound address is not TCP: %v (%T)", ln.Addr(), ln.Addr())
	}
	if !tcp.IP.IsLoopback() {
		t.Fatalf("bound to %v, which is not a loopback address", tcp.IP)
	}
	if tcp.Port == 0 {
		t.Fatal("bound port is 0 — expected the kernel to have assigned one by the time Listen returns")
	}
}

// --- test harness: a real HTTP server wired the same way runView wires one,
// without going through bindLoopback/signal handling, so the security
// middleware can be driven directly and quickly. ---

type testView struct {
	ts    *httptest.Server
	v     *viewServer
	token string
}

func newTestView(t *testing.T, sessionID, path string) *testView {
	t.Helper()
	tv := &testView{token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"}
	tv.v = newViewServer(sessionID, path, tv.token, "")
	// Wrap the mux itself, not each pattern — the same structure runView
	// uses. A per-pattern wrap never sees a "dirty" path request at all,
	// because http.ServeMux answers those with its own redirect before any
	// registered handler runs; wrapping the mux is what makes every request,
	// dirty path included, clear the method/Host/token checks first.
	mux := http.NewServeMux()
	mux.HandleFunc("/", tv.v.handleIndex)
	mux.HandleFunc("/events", tv.v.handleEvents)
	tv.ts = httptest.NewServer(tv.v.wrap(mux.ServeHTTP))
	// Set only after Start: the listener's real address is only known once
	// it exists, and nothing calls into the mux before the test itself
	// issues a request below.
	tv.v.host = tv.ts.Listener.Addr().String()
	t.Cleanup(tv.ts.Close)

	// runView is what normally starts the background poll loop that turns
	// new events into broadcast SSE frames; this harness wires the routes
	// directly (to drive the security middleware without going through
	// bindLoopback/signal handling), so it has to start that loop itself.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan string, 1)
	go tv.v.poll(ctx, time.Hour, done)

	return tv
}

func (tv *testView) req(t *testing.T, method, path, token string) *http.Request {
	t.Helper()
	url := tv.ts.URL + path
	if token != "" {
		if strings.Contains(path, "?") {
			url += "&token=" + token
		} else {
			url += "?token=" + token
		}
	}
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func newFixtureSession(t *testing.T) (sessionID, path string, rec *recorder.Recorder) {
	t.Helper()
	root := t.TempDir()
	sessionID = "s1"
	rec, err := recorder.Open(root, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionStart, Arch: "arm64", Kelyfos: "dev"}); err != nil {
		t.Fatal(err)
	}
	path = recorder.Path(root, sessionID)
	t.Cleanup(func() { rec.Close() })
	return sessionID, path, rec
}

// --- token required, on every route, refused when wrong or missing ---

func TestWrongOrMissingTokenRefusedOnEveryRoute(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	for _, route := range []string{"/", "/events"} {
		for _, tokenTried := range []string{"", "wrong-token-entirely", tv.token[:len(tv.token)-1] + "0"} {
			req := tv.req(t, http.MethodGet, route, tokenTried)
			resp, err := tv.ts.Client().Do(req)
			if err != nil {
				t.Fatalf("%s token=%q: %v", route, tokenTried, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with token %q: got %d, want %d", route, tokenTried, resp.StatusCode, http.StatusUnauthorized)
			}
		}
	}
}

func TestCorrectTokenAcceptedOnEveryRoute(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	req := tv.req(t, http.MethodGet, "/", tv.token)
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / with the correct token: got %d, want 200", resp.StatusCode)
	}

	// /events is a streaming route; a 200 with the right content type before
	// closing the connection is enough to prove the token was accepted here
	// too, without reading the whole stream.
	req2 := tv.req(t, http.MethodGet, "/events", tv.token)
	req2 = req2.WithContext(withTimeout(t, 5*time.Second))
	resp2, err := tv.ts.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /events with the correct token: got %d, want 200", resp2.StatusCode)
	}
	if ct := resp2.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}
}

// A Bearer header must work too — the alternative to a query-string token
// this task's own doc comment offers curl callers.
func TestBearerHeaderAcceptedAsAnAlternativeToTheQueryToken(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	req := tv.req(t, http.MethodGet, "/", "")
	req.Header.Set("Authorization", "Bearer "+tv.token)
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Bearer token: got %d, want 200", resp.StatusCode)
	}
}

// --- Host header must match the bound address, or the request is refused
// regardless of token validity (DNS rebinding defence) ---

func TestMismatchedHostRefusedEvenWithACorrectToken(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	for _, route := range []string{"/", "/events"} {
		req := tv.req(t, http.MethodGet, route, tv.token)
		req.Host = "evil.example.com:1234"
		resp, err := tv.ts.Client().Do(req)
		if err != nil {
			t.Fatalf("%s: %v", route, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with a mismatched Host and the correct token: got %d, want %d", route, resp.StatusCode, http.StatusForbidden)
		}
	}
}

// F1, found by adversarial review: http.ServeMux runs its own path-cleaning
// redirect (double slashes, "."/".." segments) *inside* ServeMux.ServeHTTP,
// before dispatching to any registered handler — so a security wrapper
// applied per-pattern (mux.HandleFunc(p, wrap(h))) never runs on a "dirty"
// path at all; ServeMux answers with its own 307 first, with none of
// wrap's method/Host/token checks evaluated. Live repro: an unauthenticated,
// wrong-Host, POST to "//" or "//events" got a 307. The fix wraps the mux
// itself (http.Server{Handler: wrap(mux.ServeHTTP)}) so every request,
// dirty path included, clears the checks before ServeMux's own routing —
// redirect or otherwise — ever runs.
func TestDirtyPathsStillGoThroughEveryCheckBeforeServeMuxsOwnRedirect(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	// The default client (tv.ts.Client()) follows redirects transparently —
	// 307 preserves method and body, so Client.Do silently re-sends the
	// request to the redirect target and resp.StatusCode ends up being the
	// *final*, post-redirect status. Against the bug this test exists to
	// catch, that final status coincidentally matches what's asserted below
	// (401/403/405), so the test gave a false PASS on the exact vulnerable
	// code it names in its own title — found by re-review, confirmed by
	// reverting the fix in a scratch clone and watching this client mask a
	// real 307 fifteen times out of fifteen. A client with CheckRedirect
	// short-circuited returns the raw first-hop response instead.
	client := &http.Client{
		Transport: tv.ts.Client().Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	dirtyPaths := []string{"//", "//events", "/a/../b", "/./", "///"}

	for _, dirty := range dirtyPaths {
		// No token, correct Host: must not be answered by a bare redirect —
		// the missing-token refusal has to fire first.
		req := tv.req(t, http.MethodGet, dirty, "")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s (no token): %v", dirty, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusMovedPermanently {
			t.Errorf("%s with no token: got %d — ServeMux's own redirect answered before the token check ran", dirty, resp.StatusCode)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s with no token: got %d, want %d", dirty, resp.StatusCode, http.StatusUnauthorized)
		}

		// Correct token, wrong Host: must not be answered by a bare redirect
		// either — the Host check has to fire regardless of path shape.
		req = tv.req(t, http.MethodGet, dirty, tv.token)
		req.Host = "evil.example.com:1234"
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("%s (wrong Host): %v", dirty, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusMovedPermanently {
			t.Errorf("%s with a mismatched Host: got %d — ServeMux's own redirect answered before the Host check ran", dirty, resp.StatusCode)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s with a mismatched Host: got %d, want %d", dirty, resp.StatusCode, http.StatusForbidden)
		}

		// Correct token, correct Host, POST: must not be answered by a bare
		// redirect either — the method check has to fire regardless of path
		// shape, matching the structural "GET/HEAD only" requirement.
		req = tv.req(t, http.MethodPost, dirty, tv.token)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("%s (POST): %v", dirty, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusMovedPermanently {
			t.Errorf("POST %s: got %d — ServeMux's own redirect answered before the method check ran", dirty, resp.StatusCode)
		}
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("POST %s: got %d, want %d", dirty, resp.StatusCode, http.StatusMethodNotAllowed)
		}
	}
}

// http.ServeMux's "/" pattern is a catch-all for anything not more
// specifically registered; handleIndex refuses that rather than silently
// rendering the report for an arbitrary path.
func TestUnknownPathIsRefusedNotSilentlyRenderedAsTheIndex(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	req := tv.req(t, http.MethodGet, "/some/other/path", tv.token)
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /some/other/path: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// --- GET and HEAD only, structurally: every other method refused on every
// route regardless of token or Host validity ---

func TestNonGetHeadMethodsRefusedOnEveryRoute(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, "TRACE"} {
		for _, route := range []string{"/", "/events"} {
			req := tv.req(t, method, route, tv.token)
			resp, err := tv.ts.Client().Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", method, route, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got %d, want %d", method, route, resp.StatusCode, http.StatusMethodNotAllowed)
			}
			if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
				t.Errorf("%s %s: Allow header = %q, want \"GET, HEAD\"", method, route, allow)
			}
		}
	}
}

func TestHeadIsAccepted(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)
	req := tv.req(t, http.MethodHead, "/", tv.token)
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HEAD /: got %d, want 200", resp.StatusCode)
	}
}

// --- the CSP header is what's actually enforced; its script hash is pinned
// against the actually-served script, not a hand-copied literal ---

func TestCSPHashMatchesTheActuallyServedScript(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	tv := newTestView(t, sessionID, path)

	req := tv.req(t, http.MethodGet, "/", tv.token)
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readAll(t, resp.Body)
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy header on the served page")
	}
	if strings.Contains(body, "innerHTML") {
		t.Fatal("the served page contains the literal substring \"innerHTML\" — the RENDER-surface condition forbids it appearing anywhere in the served JS")
	}

	start := strings.Index(body, "<script>")
	end := strings.Index(body, "</script>")
	if start < 0 || end < 0 || end < start {
		t.Fatalf("could not find a <script>...</script> block in the served page")
	}
	served := body[start+len("<script>") : end]

	sum := sha256.Sum256([]byte(served))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(csp, want) {
		t.Fatalf("CSP header %q does not pin the hash of the actually-served script (computed %s) — editing the script without updating what the CSP allows would be exactly the silent loosening this test exists to catch", csp, want)
	}
	// And the static export's own CSP meta tag must be gone — leaving it in
	// place would mean two CSPs apply and the meta's default-src 'none'
	// would block the script the header just allowed.
	if strings.Contains(body, `http-equiv="Content-Security-Policy"`) {
		t.Fatal("the served page still carries the static export's own CSP meta tag; it must be removed so only the header CSP applies")
	}
}

func TestInjectLiveFailsLoudlyIfItsAnchorsAreMissing(t *testing.T) {
	if _, err := injectLive([]byte("<html><body>no anchors here</body></html>")); err == nil {
		t.Fatal("injectLive on a page with neither anchor should fail, not silently serve an unmodified page")
	}
	// Exactly one of each anchor, both present: succeeds.
	page := staticCSPMeta + bodyClose
	out, err := injectLive([]byte(page))
	if err != nil {
		t.Fatalf("injectLive on a page with both anchors exactly once: %v", err)
	}
	if bytes.Contains(out, []byte(staticCSPMeta)) {
		t.Fatal("the static CSP meta tag survived injectLive")
	}
	if !bytes.Contains(out, []byte(viewScript)) {
		t.Fatal("viewScript was not spliced into the page")
	}
	// Two copies of an anchor is refused too — injectLive's own "exactly
	// once" promise, not "at least once".
	if _, err := injectLive([]byte(staticCSPMeta + staticCSPMeta + bodyClose)); err == nil {
		t.Fatal("injectLive with the CSP anchor present twice should fail rather than silently pick one")
	}
}

// --- SSE carries data, never markup: hostile content in the session
// reaches the client as an inert, JSON-escaped string, not as bytes a naive
// consumer could read as HTML or a terminal could read as an escape
// sequence ---

func TestSSEDeliversHostileContentAsInertJSONData(t *testing.T) {
	sessionID, path, rec := newFixtureSession(t)
	// Set before newTestView, which spawns poll()'s goroutine immediately —
	// poll reads viewPollInterval once, at startup, to build its ticker
	// (view.go's time.NewTicker(viewPollInterval)), so setting it afterward
	// races that read under -race (found live: WARNING: DATA RACE between
	// this line and view.go:461, two other tests below had the identical
	// bug).
	viewPollInterval = 20 * time.Millisecond
	defer func() { viewPollInterval = time.Second }()
	tv := newTestView(t, sessionID, path)

	req := tv.req(t, http.MethodGet, "/events", tv.token)
	req = req.WithContext(withTimeout(t, 10*time.Second))
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)

	const hostile = "<script>alert(1)</script>\x07\x1b[31mpwned\x1b[0m\"'quote"
	if err := rec.Append(recorder.Event{Type: recorder.TypeFileWrite, Path: hostile, Bytes: 1}); err != nil {
		t.Fatal(err)
	}

	raw := readSSEFrame(t, reader, "update")

	// The wire bytes themselves must never carry a raw control byte or an
	// unescaped angle bracket — encoding/json escapes both by default, and
	// this is the check that nobody turned that off.
	if bytes.ContainsAny(raw, "\x07\x1b") {
		t.Fatalf("raw SSE bytes contain a literal control byte: %q", raw)
	}
	if bytes.Contains(raw, []byte("<script>")) {
		t.Fatalf("raw SSE wire bytes contain a literal, unescaped <script> tag — should be JSON-escaped: %q", raw)
	}

	var msg struct {
		Count int      `json:"count"`
		Head  string   `json:"head"`
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("SSE data line is not valid JSON: %v\nraw: %s", err, raw)
	}
	if len(msg.Lines) == 0 {
		t.Fatal("no lines in the update message")
	}
	got := msg.Lines[len(msg.Lines)-1]
	// proto.SafeText quotes the whole field once it contains a control
	// byte, so the decoded string is a Go-syntax-quoted representation —
	// still containing the literal substrings "<script>" and the quote
	// characters (those are not control bytes; proto.SafeText's job is
	// control-byte safety for a terminal, not HTML safety, which textContent
	// provides on the client), but with every control byte turned into a
	// visible backslash escape rather than a live one.
	if strings.ContainsAny(got, "\x07\x1b") {
		t.Fatalf("the decoded line still contains a literal control byte: %q", got)
	}
	if !strings.Contains(got, `\x07`) && !strings.Contains(got, `\a`) {
		t.Fatalf("expected the control byte to survive as a visible escape after proto.SafeText, got: %q", got)
	}
}

func TestSSECatchesUpNewClientsWithoutReplayingOldEvents(t *testing.T) {
	// A client connecting after several events already happened should not
	// receive a flood of stale "update" frames for events the initial page
	// render already showed — only what's new from here.
	sessionID, path, rec := newFixtureSession(t)
	if err := rec.Append(recorder.Event{Type: recorder.TypeCommandStart, Cmd: []string{"echo", "hi"}}); err != nil {
		t.Fatal(err)
	}
	// Set before newTestView spawns poll()'s goroutine — see the comment on
	// the identical fix in TestSSEDeliversHostileContentAsInertJSONData.
	viewPollInterval = 20 * time.Millisecond
	defer func() { viewPollInterval = time.Second }()
	tv := newTestView(t, sessionID, path)

	// Let at least one poll tick happen before connecting, so lastCount is
	// already caught up to the two pre-existing events.
	time.Sleep(80 * time.Millisecond)

	req := tv.req(t, http.MethodGet, "/events", tv.token)
	req = req.WithContext(withTimeout(t, 10*time.Second))
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)

	if err := rec.Append(recorder.Event{Type: recorder.TypeFileWrite, Path: "only-this-one", Bytes: 1}); err != nil {
		t.Fatal(err)
	}
	raw := readSSEFrame(t, reader, "update")
	var msg struct {
		Lines []string `json:"lines"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	if len(msg.Lines) != 1 {
		t.Fatalf("expected exactly 1 new line (only the event appended after connecting), got %d: %v", len(msg.Lines), msg.Lines)
	}
	if !strings.Contains(msg.Lines[0], "only-this-one") {
		t.Fatalf("the one new line does not mention the new event: %v", msg.Lines)
	}
}

func TestSessionEndBroadcastsEndAndStopsFurtherUpdates(t *testing.T) {
	sessionID, path, rec := newFixtureSession(t)
	// Set before newTestView spawns poll()'s goroutine — see the comment on
	// the identical fix in TestSSEDeliversHostileContentAsInertJSONData.
	viewPollInterval = 20 * time.Millisecond
	defer func() { viewPollInterval = time.Second }()
	tv := newTestView(t, sessionID, path)

	req := tv.req(t, http.MethodGet, "/events", tv.token)
	req = req.WithContext(withTimeout(t, 10*time.Second))
	resp, err := tv.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)

	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "shutdown", DurationMS: 5}); err != nil {
		t.Fatal(err)
	}
	raw := readSSEFrame(t, reader, "end")
	var msg struct {
		Count  int    `json:"count"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Reason != "shutdown" {
		t.Errorf("end reason = %q, want %q", msg.Reason, "shutdown")
	}
}

// --- runView's own lifecycle: exits on session.end, exits on idle timeout,
// prints the token exactly once, in the URL, never as a bare CLI argument
// this test could grep out of os.Args ---

func TestRunViewExitsWhenTheSessionEnds(t *testing.T) {
	sessionID, path, rec := newFixtureSession(t)
	viewPollInterval = 20 * time.Millisecond
	defer func() { viewPollInterval = time.Second }()

	// A plain bytes.Buffer here is a real data race under -race: runView's
	// goroutine keeps writing to it (its own progress lines) for the rest of
	// the test, and waitFor below reads it concurrently, before the `done`
	// channel receive gives the two goroutines a synchronization point.
	// syncBuffer below is a mutex-guarded stand-in for exactly that window;
	// production code never has this problem (viewCmd passes os.Stdout, and
	// nothing else ever reads it concurrently).
	out := &syncBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runView(ctx, sessionID, path, time.Hour, out) }()

	// Give runView a moment to bind and print the URL before ending the
	// session, so the end is observed by an already-running poll loop
	// rather than racing server start-up.
	waitFor(t, 5*time.Second, func() bool { return strings.Contains(out.String(), "kelyfos view: http://") })

	if err := rec.Append(recorder.Event{Type: recorder.TypeSessionEnd, Reason: "done", DurationMS: 1}); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runView returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runView did not exit after session.end")
	}
	if !strings.Contains(out.String(), "stopping (the session ended)") {
		t.Errorf("expected an explicit \"stopping (the session ended)\" line, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "?token=") {
		t.Errorf("the printed URL does not carry ?token=:\n%s", out.String())
	}
}

func TestRunViewExitsAfterIdleTimeoutWithNobodyConnected(t *testing.T) {
	sessionID, path, _ := newFixtureSession(t)
	viewPollInterval = 20 * time.Millisecond
	defer func() { viewPollInterval = time.Second }()

	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runView(ctx, sessionID, path, 150*time.Millisecond, &out) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runView returned an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runView did not exit after its idle timeout")
	}
	if !strings.Contains(out.String(), "idle for more than") {
		t.Errorf("expected an idle-timeout stop reason, got:\n%s", out.String())
	}
}

// --- helpers ---

// String is a non-destructive read of syncBuffer's content (unlike take,
// which empties it) — what the one test above needs, since it reads
// runView's output while runView's own goroutine is still writing to it. A
// plain bytes.Buffer there is a genuine data race; syncBuffer already exists
// (servemcpteam.go) for the identical problem elsewhere in this package.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func withTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// readSSEFrame reads lines from an SSE stream until it finds one carrying
// the wanted event name, then returns that frame's raw "data:" payload
// bytes (without the "data: " prefix or the trailing blank line).
func readSSEFrame(t *testing.T, r *bufio.Reader, wantEvent string) []byte {
	t.Helper()
	deadline := time.Now().Add(9 * time.Second)
	var sawEvent bool
	for time.Now().Before(deadline) {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE stream: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case strings.HasPrefix(line, "event: "):
			sawEvent = strings.TrimPrefix(line, "event: ") == wantEvent
		case strings.HasPrefix(line, "data: "):
			if sawEvent {
				return []byte(strings.TrimPrefix(line, "data: "))
			}
		}
	}
	t.Fatalf("timed out waiting for an SSE %q event", wantEvent)
	return nil
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true")
}

// --- viewLogLine: the live feed's own control-byte defence ---

func TestViewLogLineAppliesSafeTextToControlBytes(t *testing.T) {
	line := viewLogLine(recorder.Event{
		Type:  recorder.TypeFileWrite,
		Path:  "evil\x1b[31m.txt",
		Agent: "a\x07gent",
	})
	if strings.ContainsAny(line, "\x1b\x07") {
		t.Fatalf("viewLogLine let a raw control byte through: %q", line)
	}
}

func TestViewLogLineHasNoPanicOnEveryKnownEventType(t *testing.T) {
	// A cheap regression guard: every event type this file names should
	// format without panicking, whatever fields happen to be zero.
	types := []string{
		recorder.TypeSessionStart, recorder.TypeSessionReady, recorder.TypeSessionEnd,
		recorder.TypeCommandStart, recorder.TypeCommandExit, recorder.TypeFileWrite,
		recorder.TypeEgressAttempt, recorder.TypeSecretUse, recorder.TypeTeamMessage,
		recorder.TypeTeamRefused, recorder.TypeTeamSpawn, recorder.TypeResourceOOM,
		recorder.TypeResourceTimeout, recorder.TypeResourceSummary, "some.unknown.type",
	}
	for _, ty := range types {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("viewLogLine panicked on %s: %v", ty, r)
				}
			}()
			_ = viewLogLine(recorder.Event{Type: ty})
		}()
	}
}

func TestNewViewTokenIs256BitsHexEncoded(t *testing.T) {
	tok, err := newLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 { // 32 bytes, hex-encoded
		t.Fatalf("token %q is %d hex characters, want 64 (256 bits)", tok, len(tok))
	}
	tok2, err := newLocalToken()
	if err != nil {
		t.Fatal(err)
	}
	if tok == tok2 {
		t.Fatal("two calls to newLocalToken produced the same token")
	}
}
