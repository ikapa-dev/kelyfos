package egress

import (
	"fmt"
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
	// A scope that is not in normal form covers nothing (P7-14). ParseSecretSpec
	// refuses one before it can exist, so this is the second lock on the same
	// door: a Scope built by hand, or by a parser added later that forgets the
	// rule, withholds the credential rather than approving a request the bound
	// prefix does not literally cover.
	if canonicalScopePath(s.Path) != nil {
		return false, WithheldPath
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
// sends URL.EscapedPath() upstream — the two can differ, and this proxy matches
// against the former while the latter, verbatim, is what a real origin server
// receives and re-segments in its own way.
//
// That re-segmentation cannot be enumerated. Earlier this function tried:
// reject a literal "%2f" or "%2e" in the escaped path, then require the decoded
// path to already be in path.Clean's normal form. That enumerated what *Go's
// own parser* treats specially — but a real origin server is free to
// re-segment on bytes Go's parser has no opinion on at all, and every one of
// these passed the old check while a real server would have routed the request
// somewhere the bound prefix never approved:
//
//   - "/repos/x/..;/..;/admin" — ';' is an ordinary, unencoded path character
//     to Go, so path.Clean leaves it alone. Tomcat and Jetty strip everything
//     from the first ';' in a segment before routing, see two ".." segments,
//     and land on /admin.
//   - "/repos/x%5c..%5c..%5cadmin" — %5c decodes to a literal backslash, which
//     path.Clean does not treat as a separator. IIS and .NET do, and land on
//     /admin.
//   - "/repos/x%c0%af..%c0%afadmin" — %c0%af is an overlong, invalid UTF-8
//     encoding of '/'. Go decodes it to two raw bytes and stops there; a
//     server with a lenient legacy decoder reads it as '/' and lands on
//     /admin.
//
// Those three are illustrations, not the list. Any enumeration of "the
// encodings that matter" is a claim about every HTTP stack an operator might
// bind a credential to, and this project cannot make that claim. So this
// function does not enumerate what to reject; it allowlists the narrow set of
// bytes that are safe on every stack, and rejects everything else, including
// every percent-encoding this project has not specifically vetted for safety.
// The one exception is "%20": an ordinary encoded space in a repository name
// is a legitimate, existing use, and refusing it would only teach people to
// widen the binding to the whole domain instead — a worse outcome than the
// narrow exception is.
func literalAndNormal(escaped, decoded string) bool {
	for i := 0; i < len(escaped); i++ {
		b := escaped[i]
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		case b == '-' || b == '.' || b == '_' || b == '~':
		case b == '/':
		case b == '%' && i+2 < len(escaped) && escaped[i+1] == '2' && (escaped[i+2] == '0'):
			i += 2
		default:
			return false
		}
	}
	// path.Clean does not know about the bytes just excluded above, but it is
	// still the right check for what it always caught: a literal, unencoded
	// ".." or "." segment, which the character allowlist does not exclude on
	// its own — '.' is in the allowed set. It strips a trailing slash, which
	// is normal form for asking after a collection rather than a traversal, so
	// that is allowed back.
	c := path.Clean(decoded)
	return c == decoded || c+"/" == decoded
}

// canonicalScopePath reports why a bound path is not in the form requests are
// compared in, or nil if it is (P7-14).
//
// covered trims exactly one trailing slash off a prefix before comparing, so a
// scope written "/repos//" — a plausible typo, not a contrived input — approved
// "/repos/", which an origin that strips matrix parameters or collapses
// separators resolves to "/repos": not beneath the literal bound prefix. The
// fix is not a second trim; it is that a scope which is not already in normal
// form has no meaning here, and the honest answer to a typo in a credential
// scope is a refusal that says what to write, not a guess at what was meant.
//
// Normal form is path.Clean's, with the trailing slash that names a collection
// allowed back — the same rule literalAndNormal applies to a request. Which
// characters a scope may carry is the grammar's business (D44: ":" and "+" are
// ordinary path characters), not this check's.
func canonicalScopePath(p string) error {
	if p == "" || p[0] != '/' {
		return fmt.Errorf("a scope path must start with \"/\"")
	}
	c := path.Clean(p)
	// "/" is its own collection form: "//" is the doubled-slash typo, not
	// "/" plus the slash that names a collection.
	if c == p || (c != "/" && c+"/" == p) {
		return nil
	}
	want := c
	if strings.HasSuffix(p, "/") && c != "/" {
		want += "/"
	}
	return fmt.Errorf("scope path %q is not in normal form (a doubled slash, or a \".\" or \"..\" segment); write it as %q", p, want)
}

// covered reports whether a normalised path is beneath a bound prefix, on a
// segment boundary. The prefix is canonical by the time it gets here — covers
// checks, and ParseSecretSpec refuses one that is not — which is what makes
// the one-slash trim below exact rather than a guess (P7-14).
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
