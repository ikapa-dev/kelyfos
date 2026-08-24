package egress

import (
	"net/http"
	"path"
	"strings"
)

// Scope narrows where a bound credential may be spent (P6-4).
//
// A secret with an empty Scope is what every secret was before v1.0: bound to a
// domain and its subdomains, attached to any request that reaches it. A scope
// turns "one domain" into "one endpoint": a path beneath one exact host.
//
// There is no method set here, deliberately. D44 cut it from the grammar — the
// policy file cannot carry a comma and "+" is an ordinary path character — and
// a field nothing can populate is a feature that does not exist wearing the
// clothes of one.
//
// It narrows *injection*, never egress. A request outside the scope still goes;
// it simply goes without the credential, and the record says so. Refusing the
// request instead would be a second egress policy living in the credential
// grammar, and `allow` is where egress is decided.
type Scope struct {
	// Path, when set, is the prefix a request path must be covered by, and it
	// also means the host must match exactly rather than by suffix: naming a
	// path is naming an endpoint, and letting it expand to subdomains would
	// contradict the thing it was written to do.
	Path string
}

// Why a credential was not attached, recorded so the failure is diagnosable.
// The alternative is what this project keeps finding and fixing: a credential
// that silently does not attach, a request that goes out unauthenticated, and a
// 401 from somewhere else as the only symptom.
const (
	WithheldPath     = "path_not_covered"
	WithheldNotPlain = "path_not_literal"
	// WithheldUnencrypted is not a scope decision — it is decided before the
	// scope is consulted, and it has always been the behaviour. A credential is
	// attached only on the terminated path, so a guest that reaches a
	// secret-bound domain over plain HTTP gets no credential. That is right:
	// nobody should put a bearer token on a plaintext request. It has simply
	// never been said anywhere, so a user who bound a secret and used
	// http:// saw an unauthenticated request and no reason for it.
	WithheldUnencrypted = "not_encrypted"
	// WithheldHostMismatch is the one that was a live defect rather than a new
	// rule. See sameHost in terminate.go.
	WithheldHostMismatch = "host_mismatch"
)

// covers reports whether a request is inside the scope, and if not, why.
func (s Scope) covers(req *http.Request) (bool, string) {
	if s.Path == "" {
		return true, ""
	}
	if !literalAndNormal(req.URL.EscapedPath(), req.URL.Path) {
		return false, WithheldNotPlain
	}
	if !covered(s.Path, req.URL.Path) {
		return false, WithheldPath
	}
	return true, ""
}

// literalAndNormal reports whether a decoded path can be compared against a
// configured prefix at all.
//
// This is the whole security of endpoint locking, and it is not obvious, so it
// is measured rather than argued. Go decodes a request target into URL.Path and
// sends URL.EscapedPath() upstream — the two can differ, and every way they
// differ is a way for the path this proxy *matched* to not be the path the
// server *routes*:
//
//	request line              URL.Path (matched)   sent upstream
//	/repos/../admin           /repos/../admin      /repos/../admin      → /admin
//	/repos/%2e%2e/admin       /repos/../admin      /repos/%2e%2e/admin  → /admin
//	/repos%2f..%2fadmin       /repos/../admin      /repos%2f..%2fadmin  → /admin
//
// All three have a URL.Path beginning "/repos/", so a naive prefix match hands
// a credential bound to /repos/ to a request the server resolves to /admin.
//
// So a credential is attached only to a path that is literal and already in
// normal form: no percent-encoded slash or dot, which are the encodings that
// let a server re-segment what was matched, and nothing for path.Clean to do.
// Other encodings are harmless here and stay allowed, because a repository name
// containing a space is an ordinary request and refusing it would push people
// to widen the binding instead.
func literalAndNormal(escaped, decoded string) bool {
	low := strings.ToLower(escaped)
	if strings.Contains(low, "%2f") || strings.Contains(low, "%2e") {
		return false
	}
	// path.Clean strips a trailing slash, which is normal form for asking after
	// a collection rather than a traversal, so it is allowed back.
	c := path.Clean(decoded)
	return c == decoded || c+"/" == decoded
}

// covered reports whether a normalised path is beneath a bound prefix, on a
// segment boundary.
//
// The boundary matters: a bare strings.HasPrefix of "/repos" also covers
// "/repos-private", which is the mistake that makes endpoint locking look like
// it works while binding a credential to somebody else's tree. A prefix ending
// in "/" covers everything beneath it and the collection itself; a prefix
// without one names that exact path and nothing else.
func covered(prefix, p string) bool {
	if !strings.HasSuffix(prefix, "/") {
		return p == prefix
	}
	return p == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(p, prefix)
}
