package shim

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/p4r4n0rm4l/KelyfOS/internal/hostile"
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
// If the answer is a token, these turn green. If the answer is a ceiling, the
// ceiling case turns green and the token case stays as a recorded decision.

// drive runs one request against the handler with no network and no VM.
func drive(t *testing.T, h http.Handler, method, target, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
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
	return New(Policy{Arch: "aarch64", Flavor: "dev", Vcpus: 2, MemMiB: 512})
}

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
	// so a nil sb is never dereferenced.
	const already = 64
	for i := 0; i < already; i++ {
		s.boxes[fmt.Sprintf("box-%d", i)] = &box{}
	}

	code, body := drive(t, s.Handler(), "POST", "/sandboxes", `{}`)

	// The request cannot succeed here — there is no image to boot from — so the
	// question is *why* it failed. A refusal names the ceiling. Anything else
	// means the shim went on to try, and on a machine with images it would have
	// built the sixty-fifth machine.
	problem := ""
	if !mentionsAny(body, "too many", "limit", "ceiling", "at capacity", "maximum") {
		problem = fmt.Sprintf("with %d sandboxes already registered, POST /sandboxes answered %d %q — "+
			"it went on to build one rather than refusing on a count", already, code, body)
	}
	hostile.Holds(t, "shim/sandbox-count", problem)
}

// H-6. No route asks who is calling.
//
// Recorded rather than argued: the shim is documented as a tool for a machine
// you already trust. What the fixture pins is that the decision is still the
// one in force — if a token is ever added, this case turns green and its line
// comes off the ledger, and if it is not, the ledger is where the decision is
// visible instead of being visible only to somebody reading the source.
func TestHostileShimAsksWhoIsCalling(t *testing.T) {
	s := hostileShim(t)
	h := s.Handler()

	problem := ""
	for _, route := range []struct{ method, target string }{
		{"GET", "/sandboxes"},
		{"POST", "/sandboxes"},
		{"GET", "/health"},
	} {
		code, _ := drive(t, h, route.method, route.target, `{}`)
		if code != http.StatusUnauthorized {
			problem = fmt.Sprintf("%s %s answered %d with no credential presented; no route asks",
				route.method, route.target, code)
		}
	}
	hostile.Holds(t, "shim/no-authentication", problem)
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
