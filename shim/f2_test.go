package shim

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P7-17/F2 — the E2B shim had no cross-site request defence.
//
// The shim serves on 127.0.0.1:3000 and its middleware chain was
// logging(authenticated(mux)) with authentication off by default. Localhost
// plus no auth is the exact configuration a web page can reach, and two routes
// are reachable cross-origin without a preflight:
//
//	POST /files  — multipart/form-data is a CORS-"simple" request, so a plain
//	               <form> in any page the developer visits writes a file into
//	               the live sandbox: /work/.git/hooks/pre-commit, say.
//	POST /sandboxes — the body was not required to parse at all, so an empty
//	               cross-origin POST booted a microVM, up to MaxSandboxes.
//
// The responses are not readable cross-origin. That does not matter: the
// writes land, and a planted file the agent will later read is the better
// outcome for an attacker anyway.
//
// bound is the address the fixtures pretend the listener took.
const bound = "127.0.0.1:3000"

// f2Shim is hostileShim with the bind address the Host check needs. It carries
// no token so that the browser checks are tested on their own; the ordering
// test below sets one explicitly.
func f2Shim(t *testing.T) *Server {
	t.Helper()
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	return New(Policy{Arch: "aarch64", Flavor: "dev", Vcpus: 2, MemMiB: 512, Addr: bound})
}

// driveHeaders is drive with a caller-chosen Host and header set, which is the
// whole point here: what separates a browser from an SDK is the headers.
func driveHeaders(t *testing.T, h http.Handler, method, target, body, host string, hdr map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, strings.TrimSpace(rr.Body.String())
}

// The two routes a page can reach, times the three headers only a browser
// sends. No SDK sends any of them.
func TestF2_ACrossSiteRequestIsRefused(t *testing.T) {
	h := f2Shim(t).Handler()
	routes := []struct{ method, target string }{
		{"POST", "/sandboxes"},
		{"POST", "/files?path=/work/.git/hooks/pre-commit"},
		{"GET", "/sandboxes"},
		{"GET", "/health"},
	}
	browsers := []struct {
		name string
		hdr  map[string]string
	}{
		{"Sec-Fetch-Site: cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"Sec-Fetch-Site: same-site", map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"an Origin header at all", map[string]string{"Origin": "http://evil.example"}},
		{"an Origin naming the shim itself", map[string]string{"Origin": "http://127.0.0.1:3000"}},
		{"a form POST from a page", map[string]string{
			"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site",
			"Content-Type": "multipart/form-data; boundary=x"}},
	}
	for _, route := range routes {
		for _, b := range browsers {
			t.Run(route.method+" "+route.target+" with "+b.name, func(t *testing.T) {
				code, body := driveHeaders(t, h, route.method, route.target, `{}`, bound, b.hdr)
				if code != http.StatusForbidden {
					t.Errorf("answered %d, want 403 — a browser reached the shim\n  %s", code, body)
				}
			})
		}
	}
}

// The other side of the same rule: an SDK, curl or the acceptance suite sends
// none of those headers and must be unaffected. A defence that also refuses the
// only client the shim has is not a defence.
func TestF2_AnOrdinaryClientIsUnaffected(t *testing.T) {
	h := f2Shim(t).Handler()
	for _, c := range []struct {
		name string
		hdr  map[string]string
		host string
	}{
		{"no browser headers at all", nil, bound},
		{"Sec-Fetch-Site: none (a typed URL)", map[string]string{"Sec-Fetch-Site": "none"}, bound},
		{"Sec-Fetch-Site: same-origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, bound},
		{"Host: localhost:3000", nil, "localhost:3000"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if code, body := driveHeaders(t, h, "GET", "/health", "", c.host, c.hdr); code == http.StatusForbidden {
				t.Errorf("a legitimate client was refused: %d\n  %s", code, body)
			}
		})
	}
}

// DNS rebinding is the attack the Host check exists for, and it is the one
// attack the Origin and Sec-Fetch-Site checks cannot see: a page at
// http://evil.example:3000 whose name has been rebound to 127.0.0.1 is
// same-origin with itself, so it sends Sec-Fetch-Site: same-origin and no
// Origin at all. What it cannot forge is the Host header, which comes from its
// own URL.
func TestF2_ARebindableHostHeaderIsRefused(t *testing.T) {
	h := f2Shim(t).Handler()
	for _, host := range []string{
		"evil.example:3000",
		"evil.example",
		"kelyfos.localhost:3000",
		"127.0.0.1.nip.io:3000",
		"127.0.0.1:9999", // the right address, the wrong port
		"",
	} {
		t.Run("Host: "+host, func(t *testing.T) {
			code, body := driveHeaders(t, h, "GET", "/health", "", host,
				map[string]string{"Sec-Fetch-Site": "same-origin"})
			if code != http.StatusForbidden {
				t.Errorf("Host %q answered %d, want 403\n  %s", host, code, body)
			}
		})
	}
}

// A Server that was never told what address it bound to refuses everything.
// The alternative — skipping the check when the field is empty — is a defence
// that silently switches itself off, which is the shape of half this review.
func TestF2_AShimThatDoesNotKnowItsAddressRefusesEverything(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	h := New(Policy{Arch: "aarch64", Flavor: "dev", Vcpus: 2, MemMiB: 512}).Handler()
	if code, body := driveHeaders(t, h, "GET", "/health", "", bound, nil); code != http.StatusForbidden {
		t.Errorf("answered %d with no bound address recorded, want 403\n  %s", code, body)
	}
}

// Order matters: the browser checks run before the token check, so a page that
// somehow learned the token still gets nowhere, and the refusal a browser sees
// never depends on a credential comparison.
func TestF2_TheBrowserChecksRunBeforeTheTokenCheck(t *testing.T) {
	const token = "a-secret-the-caller-must-know"
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	h := New(Policy{Arch: "aarch64", Flavor: "dev", Vcpus: 2, MemMiB: 512,
		Addr: bound, Token: token}).Handler()

	code, body := driveHeaders(t, h, "POST", "/sandboxes", `{}`, bound, map[string]string{
		"Origin": "http://evil.example", "Authorization": "Bearer " + token})
	if code != http.StatusForbidden {
		t.Errorf("a cross-site request carrying the right token answered %d, want 403\n  %s", code, body)
	}

	code, body = driveHeaders(t, h, "POST", "/sandboxes", `{}`, bound, map[string]string{
		"Origin": "http://evil.example"})
	if code != http.StatusForbidden {
		t.Errorf("a cross-site request with no token answered %d, want 403 rather than 401\n  %s", code, body)
	}
}

// createSandbox discarded the decode error, so a body that is not JSON booted a
// microVM. The request never had to parse to cost the host a machine.
func TestF2_ABodyThatIsNotJSONIsRefusedRatherThanBooted(t *testing.T) {
	h := f2Shim(t).Handler()
	for _, body := range []string{
		"not json at all",
		"<form>",
		`{"templateID":`,
		`{"templateID":"x"} trailing garbage`,
	} {
		t.Run(body, func(t *testing.T) {
			code, got := driveHeaders(t, h, "POST", "/sandboxes", body, bound, nil)
			if code != http.StatusBadRequest {
				t.Errorf("answered %d to a body that is not JSON, want 400\n  %s", code, got)
			}
		})
	}
	// An absent body is not a malformed one: `curl -X POST /sandboxes` with no
	// -d has always meant "the defaults", and still does. It gets as far as
	// trying to boot, which in this fixture fails on the image.
	if code, got := driveHeaders(t, h, "POST", "/sandboxes", "", bound, nil); code == http.StatusBadRequest {
		t.Errorf("an empty body was refused as malformed: %s", got)
	}
}
