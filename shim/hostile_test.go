package shim

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/hostile"
)

// The hostile corpus for the E2B-compatible surface (P6-22, finding H-6).
//
// This is the only door in the product that a machine other than this one can
// knock on. Everything else — the CLI, the MCP bridge, the team broker — is
// reached by a process on the host or by a guest through a vsock the host owns.
// The shim listens on TCP.
//
// Two halves, and D46 confirmed both are present at HEAD against the audit's
// note that one had moved: `git diff babec8f..HEAD -- shim/` is five lines of
// audit wiring, and nothing about limits or authentication is among them.
//
// A note on what these fixtures do NOT assert. That the shim listens without
// authentication is documented and deliberate — it is a developer tool for a
// machine you already trust, and docs/e2b-shim.md says so twice. The fixture
// does not argue with that decision; it pins the *consequence*, which is that
// anything able to reach the port can spend the host's memory without limit.
// That is what happened: P6-25 added the ceiling, so that case is green, and a
// token can now be required with KELYFOS_SHIM_TOKEN — but unauthenticated stays
// the default, so the token case remains on the ledger as the recorded decision
// rather than as an open defect.

// drive runs one request against the handler with no network and no VM.
//
// The Host is set because since P7-17/F2 every route checks it: httptest's own
// default is "example.com", which is a name, and a name in a Host header is
// exactly what the DNS-rebinding check refuses. A fixture that did not name a
// Host was a fixture that could no longer reach a handler at all.
// The token is carried because since P7-17/F2 every route requires one by
// default: driveNoCredential is the fixture that deliberately does not.
func drive(t *testing.T, h http.Handler, method, target, body string) (int, string) {
	t.Helper()
	req := driveRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer "+fixtureToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

// driveNoCredential is drive with nothing to prove who is calling.
func driveNoCredential(t *testing.T, h http.Handler, method, target, body string) (int, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, driveRequest(method, target, body))
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

func driveRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = bound
	return req
}

// hostileShim builds a server that cannot reach a machine.
//
// KELYFOS_CACHE points the sandbox root at an empty directory, so sandbox.New
// fails on its first stat of the image artifacts — before the jailer, before
// Firecracker, before anything touches the host. The policy leaves Allow and
// CPUQuota empty on purpose: either one would send boot() reaching for nftables
// or cgroups, and a hostile fixture that needs sudo is one nobody runs.
func hostileShim(t *testing.T) *Server {
	t.Helper()
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	return New(Policy{Arch: "aarch64", Flavor: "dev", Vcpus: 2, MemMiB: 512,
		Addr: bound, Token: fixtureToken})
}

// fixtureToken stands in for what the CLI mints per process. Every fixture in
// this file carries it, because a shim that authenticates nobody is no longer
// what `kelyfos shim` builds (P7-17/F2).
const fixtureToken = "a-secret-the-caller-must-know"

// H-6. Nothing bounds how many sandboxes one caller may ask for.
//
// A sandbox is a microVM: memory, a disk image, a TAP device, a process. The
// policy carries per-sandbox ceilings and none for the count of them, so the
// arithmetic is whatever the caller chooses times whatever the policy allows.
// This asks the question a fixture can answer without booting anything: with the
// map already full of sandboxes, does the next request get refused, or does it
// go on to try to build one?
func TestHostileSandboxCountIsBounded(t *testing.T) {
	s := hostileShim(t)

	// Pre-existing boxes, reachable because this is the same package. Safe:
	// createSandbox only writes its own new key and listSandboxes ranges keys,
	// so a nil sb is never dereferenced. The count comes from the constant, so
	// a ceiling that moves does not leave this asserting against the old one.
	already := MaxSandboxes
	for i := 0; i < already; i++ {
		s.boxes[fmt.Sprintf("box-%d", i)] = &box{}
	}

	code, body := drive(t, s.Handler(), "POST", "/sandboxes", `{}`)

	// The request cannot succeed here — there is no image to boot from — so the
	// question is *why* it failed. A refusal names the ceiling. Anything else
	// means the shim went on to try, and on a machine with images it would have
	// built one more machine than its ceiling.
	problem := ""
	if !mentionsAny(body, "too many", "limit", "ceiling", "at capacity", "maximum") {
		problem = fmt.Sprintf("with %d sandboxes already registered, POST /sandboxes answered %d %q — "+
			"it went on to build one rather than refusing on a count", already, code, body)
	}
	hostile.Holds(t, "shim/sandbox-count", problem)
}

// H-6. No route asks who is calling.
//
// This was recorded rather than argued for three phases: the shim was
// documented as a tool for a machine you already trust, so the fixture pinned
// the *decision* and its line sat on the ledger. P7-17/F2 changed the decision
// — a token is minted per process unless --insecure-no-token is typed — so the
// case holds now and the line came off in the commit that made it hold, which
// is the only way the ledger is allowed to shrink.
func TestHostileShimAsksWhoIsCalling(t *testing.T) {
	s := hostileShim(t)
	h := s.Handler()

	problem := ""
	for _, route := range []struct{ method, target string }{
		{"GET", "/sandboxes"},
		{"POST", "/sandboxes"},
		{"GET", "/health"},
		{"GET", "/files"},
		{"DELETE", "/sandboxes/abcd1234"},
	} {
		code, _ := driveNoCredential(t, h, route.method, route.target, `{}`)
		if code != http.StatusUnauthorized {
			problem = fmt.Sprintf("%s %s answered %d with no credential presented; no route asks",
				route.method, route.target, code)
		}
	}
	hostile.Holds(t, "shim/no-authentication", problem)
}

// Every route asks for the token — including the one that answers before any
// sandbox exists — and a wrong token is refused exactly as an absent one is.
func TestEveryRouteRequiresTheToken(t *testing.T) {
	s := hostileShim(t)
	h := s.Handler()

	for _, route := range []struct{ method, target string }{
		{"GET", "/sandboxes"},
		{"POST", "/sandboxes"},
		{"GET", "/health"},
		{"GET", "/files"},
	} {
		if code, _ := driveNoCredential(t, h, route.method, route.target, `{}`); code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d without the token", route.method, route.target, code)
		}
		code, _ := driveAuth(t, h, route.method, route.target, "wrong-token")
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d to the wrong token", route.method, route.target, code)
		}
		code, _ = driveAuth(t, h, route.method, route.target, fixtureToken)
		if code == http.StatusUnauthorized {
			t.Errorf("%s %s refused the right token", route.method, route.target)
		}
	}
}

func driveAuth(t *testing.T, h http.Handler, method, target, token string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Host = bound
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

func mentionsAny(haystack string, needles ...string) bool {
	low := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
