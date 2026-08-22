package egress

import "testing"

func TestAllowlistMatchesSubdomains(t *testing.T) {
	p := Policy{Allow: []string{"github.com", "pypi.org"}}
	for _, host := range []string{"github.com", "api.github.com", "raw.githubusercontent.com.github.com", "pypi.org"} {
		if !p.allowsHost(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
	// The near-misses that matter: a suffix match must not be a substring match,
	// or "notgithub.com" and "github.com.evil.net" would both sail through.
	for _, host := range []string{"notgithub.com", "github.com.evil.net", "evil.net", "githubXcom"} {
		if p.allowsHost(host) {
			t.Errorf("%s must NOT be allowed", host)
		}
	}
}

func TestAllowlistIsCaseAndDotInsensitive(t *testing.T) {
	p := Policy{Allow: []string{"GitHub.com."}}
	for _, host := range []string{"github.com", "API.GITHUB.COM", "github.com."} {
		if !p.allowsHost(host) {
			t.Errorf("%s should be allowed", host)
		}
	}
}

func TestWildcardPrefixIsAccepted(t *testing.T) {
	// Someone will write it, and it should mean what they expect rather than
	// silently matching nothing.
	p := Policy{Allow: []string{"*.github.com"}}
	if !p.allowsHost("api.github.com") {
		t.Error("*.github.com should allow api.github.com")
	}
}

func TestEmptyAllowlistAllowsNothing(t *testing.T) {
	p := Policy{}
	if p.allowsHost("github.com") {
		t.Error("an empty allowlist must allow nothing")
	}
}

func TestDefaultPortsAreWebOnly(t *testing.T) {
	p := Policy{}
	for _, port := range []int{80, 443} {
		if !p.allowsPort(port) {
			t.Errorf("port %d should be allowed by default", port)
		}
	}
	for _, port := range []int{22, 25, 53, 8080, 6379} {
		if p.allowsPort(port) {
			t.Errorf("port %d must not be allowed by default", port)
		}
	}
}
