package egress

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func request(t *testing.T, method, target string) *http.Request {
	t.Helper()
	raw := method + " " + target + " HTTP/1.1\r\nHost: api.github.com\r\n\r\n"
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("building a request for %q: %v", target, err)
	}
	return req
}

// The table that decides whether endpoint locking is real.
//
// Every "false" row here is a request whose URL.Path begins with the bound
// prefix and which a server would nonetheless route somewhere else. They are
// not hypothetical: the three encoded forms were read out of Go's own parser
// before this rule was written, because the gap between the path this proxy
// matches and the path the server receives is the only way endpoint locking can
// be defeated from inside the guest.
func TestAScopedCredentialIsNotAttachedToARequestTheServerWouldRouteElsewhere(t *testing.T) {
	scope := Scope{Path: "/repos/"}

	for _, tc := range []struct {
		target string
		want   bool
		why    string
	}{
		// Inside the endpoint.
		{target: "/repos/anthropics/x", want: true},
		{target: "/repos/", want: true},
		{target: "/repos", want: true},
		// An ordinary encoded segment is not a traversal, and refusing it would
		// only teach people to bind the whole domain instead.
		{target: "/repos/my%20repo/x", want: true},

		// Traversal, plain and encoded. All three have a URL.Path under
		// /repos/ and all three reach /admin.
		{target: "/repos/../admin", want: false, why: WithheldNotPlain},
		{target: "/repos/%2e%2e/admin", want: false, why: WithheldNotPlain},
		{target: "/repos%2f..%2fadmin", want: false, why: WithheldNotPlain},
		{target: "/repos//../admin", want: false, why: WithheldNotPlain},
		{target: "/repos/./x", want: false, why: WithheldNotPlain},

		// A neighbouring tree that shares a prefix but not a segment boundary.
		{target: "/repos-private/secret", want: false, why: WithheldPath},
		// Paths are case-sensitive; hosts are not.
		{target: "/Repos/x", want: false, why: WithheldPath},
		{target: "/admin", want: false, why: WithheldPath},
	} {
		ok, why := scope.covers(request(t, "GET", tc.target))
		if ok != tc.want {
			t.Errorf("scope %q covers %q = %v, want %v (reason %q)", scope.Path, tc.target, ok, tc.want, why)
			continue
		}
		if !ok && why != tc.why {
			t.Errorf("scope %q withheld from %q for %q, want %q", scope.Path, tc.target, why, tc.why)
		}
	}
}

func TestAnExactPathScopeCoversNothingBeneathIt(t *testing.T) {
	scope := Scope{Path: "/user"}
	if ok, _ := scope.covers(request(t, "GET", "/user")); !ok {
		t.Error("an exact scope does not cover the path it names")
	}
	if ok, _ := scope.covers(request(t, "GET", "/user/emails")); ok {
		t.Error("an exact scope covers a path beneath it; it should name one path and no more")
	}
}

func TestMethodScopeRefusesTheMethodsItDoesNotName(t *testing.T) {
	scope := Scope{Methods: []string{"GET", "HEAD"}}
	for _, m := range []string{"GET", "HEAD"} {
		if ok, _ := scope.covers(request(t, m, "/anything")); !ok {
			t.Errorf("%s is named in the scope and was refused", m)
		}
	}
	for _, m := range []string{"POST", "DELETE", "PUT", "PATCH"} {
		ok, why := scope.covers(request(t, m, "/anything"))
		if ok {
			t.Errorf("%s is not named in the scope and was allowed", m)
		}
		if why != WithheldMethod {
			t.Errorf("%s withheld for %q, want %q", m, why, WithheldMethod)
		}
	}
}

// An empty scope is what every secret had before v1.0 and must keep meaning
// exactly what it meant: attach to anything that reaches the bound domain.
func TestAnEmptyScopeCoversEverything(t *testing.T) {
	var scope Scope
	for _, target := range []string{"/", "/anything", "/repos/../admin", "/x%2fy"} {
		for _, m := range []string{"GET", "POST", "DELETE"} {
			if ok, why := scope.covers(request(t, m, target)); !ok {
				t.Errorf("an unscoped credential was withheld from %s %s for %q", m, target, why)
			}
		}
	}
}
