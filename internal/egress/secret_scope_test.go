package egress

import "testing"

// The endpoint form of the grammar: NAME@host[:scheme][/path].
func TestParsingAnEndpointBinding(t *testing.T) {
	for _, tc := range []struct {
		spec       string
		wantHost   string
		wantPath   string
		wantScheme string
	}{
		{spec: "T@api.github.com/repos/", wantHost: "api.github.com", wantPath: "/repos/", wantScheme: "Bearer"},
		{spec: "T@api.github.com/user", wantHost: "api.github.com", wantPath: "/user", wantScheme: "Bearer"},
		{spec: "T@api.github.com/", wantHost: "api.github.com", wantPath: "/", wantScheme: "Bearer"},
		{spec: "T@api.github.com:basic/repos/", wantHost: "api.github.com", wantPath: "/repos/", wantScheme: "Basic"},

		// The property that makes this grammar unambiguous rather than merely
		// lucky: the split on the first "/" happens BEFORE anything looks for a
		// scheme, so a colon inside a path is part of the path. Google's
		// custom-method endpoints end in things like ":generateContent".
		{spec: "T@api.example.com/v1/models/x:generateContent",
			wantHost: "api.example.com", wantPath: "/v1/models/x:generateContent", wantScheme: "Bearer"},
		// And a "+" in a path is a "+" in a path. It was very nearly a method
		// separator, which would have silently eaten this (D44).
		{spec: "T@api.example.com/search/A+B",
			wantHost: "api.example.com", wantPath: "/search/A+B", wantScheme: "Bearer"},
		// Hosts are case-insensitive; paths are not.
		{spec: "T@API.GitHub.com/Repos", wantHost: "api.github.com", wantPath: "/Repos", wantScheme: "Bearer"},
	} {
		got, err := ParseSecretSpec(tc.spec)
		if err != nil {
			t.Errorf("ParseSecretSpec(%q): %v", tc.spec, err)
			continue
		}
		if got.Host != tc.wantHost || got.Path != tc.wantPath || got.Scheme != tc.wantScheme {
			t.Errorf("ParseSecretSpec(%q) = host %q path %q scheme %q, want %q %q %q",
				tc.spec, got.Host, got.Path, got.Scheme, tc.wantHost, tc.wantPath, tc.wantScheme)
		}
	}
}

func TestTheEndpointGrammarRefusesWhatItCannotMean(t *testing.T) {
	for _, tc := range []struct{ spec, because string }{
		{"T@*.github.com/repos", "a path binds one host exactly, so a wildcard contradicts it"},
		{"T@github.com:8080/x", "a port is not a scheme, and it has always been a loud error"},
		{"T@github.com:digest/x", "an unknown scheme"},
		{"T@github.com/x?y=1", "a query string is where credentials live"},
		{"T@github.com/x#frag", "a fragment makes the target a URL"},
		{"T@a@b.com/x", "two at-signs name no single domain"},
		{"NAME=value@github.com", "an environment variable name cannot contain ="},
		{"T@/repos", "no host"},
	} {
		if _, err := ParseSecretSpec(tc.spec); err == nil {
			t.Errorf("ParseSecretSpec(%q) was accepted; %s", tc.spec, tc.because)
		}
	}
}

// A binding that names a path binds one host, not a family of them.
func TestAnEndpointBindingDoesNotExpandToSubdomains(t *testing.T) {
	scoped := &Secret{Name: "T", Domain: "github.com", Scope: Scope{Path: "/repos/"}}
	whole := &Secret{Name: "T", Domain: "github.com"}

	if !scoped.bindsHost("github.com") {
		t.Error("an endpoint binding does not bind the host it names")
	}
	if scoped.bindsHost("api.github.com") {
		t.Error("an endpoint binding expanded to a subdomain; naming a path means naming one endpoint")
	}
	if !whole.bindsHost("api.github.com") {
		t.Error("a domain binding stopped covering its subdomains, which is a change to what every existing secret means")
	}
}

// Two credentials on one host is the obvious use of endpoint scoping, and a
// first-match-on-host rule would make the second unreachable.
func TestTwoCredentialsOnOneHostAreBothReachable(t *testing.T) {
	read := &Secret{Name: "READ", Domain: "api.example.com", Scope: Scope{Path: "/repos/"}}
	write := &Secret{Name: "WRITE", Domain: "api.example.com", Scope: Scope{Path: "/admin/"}}
	p := &Policy{Secrets: []*Secret{read, write}}

	bound := p.secretsFor("api.example.com")
	if len(bound) != 2 {
		t.Fatalf("secretsFor returned %d credentials, want both", len(bound))
	}
	if got, _ := pick(bound, requestTo(t, "GET", "/repos/x", "api.example.com"), "api.example.com"); got != read {
		t.Error("a request under /repos/ did not select the credential bound to it")
	}
	if got, _ := pick(bound, requestTo(t, "GET", "/admin/x", "api.example.com"), "api.example.com"); got != write {
		t.Error("a request under /admin/ did not select the credential bound to it — the second binding is unreachable")
	}
	got, why := pick(bound, requestTo(t, "GET", "/other", "api.example.com"), "api.example.com")
	if got != nil {
		t.Errorf("a request outside both scopes selected %q", got.Name)
	}
	if why != WithheldPath {
		t.Errorf("withheld for %q, want %q", why, WithheldPath)
	}
}
