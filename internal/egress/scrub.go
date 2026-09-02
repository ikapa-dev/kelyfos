package egress

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Echo suppression (P6-5, decision D37).
//
// KelyfOS keeps a credential's value out of the guest by construction: it lives
// on the host, the proxy attaches it on the way out, and nothing serialises it.
// There has never been anything to redact. The case construction does not reach
// is the other direction — a legitimate, allowlisted, secret-bound call whose
// *response* carries the credential back. An API that reflects the
// Authorization header, an error page quoting the token it rejected, a redirect
// carrying basic credentials in a URL. The value then lands in the guest, in
// the agent's context, and in everything the agent writes afterwards.
//
// What this is, exactly, and the name is the honest part: **echo suppression**.
// It matches the bound values and nothing else. It does not detect credentials
// in general — that would mean pattern-matching a byte stream the agent is
// about to parse, where a false positive silently corrupts a tarball or a JSON
// document and is undiagnosable from inside the guest. D37 declined that
// outright rather than deferring it, and the name here is meant to keep the
// distinction visible: this catches a credential coming *back*, not any
// credential at all.
//
// Three limits, and they are stated before anything else because a reader who
// misses them will assume more than this does:
//
//   - **The tunnelled majority is not covered and never can be.** The proxy
//     relays ciphertext for every domain with no secret bound; there is nothing
//     to match. Only a terminated connection and a plaintext request pass
//     through here at all.
//   - **A compressed body is not matchable.** Since the audit of 2026-09-01
//     (A4) the proxy asks an origin with a credential bound not to compress —
//     identity on the terminated and plain-HTTP legs' requests — so a
//     compliant origin's response is matchable end to end. An origin that
//     compresses anyway gets its response passed through unread — gzip of a
//     credential does not contain the credential — and the fact recorded via
//     OnUnscrubbable as a secret.unscrubbable event, replacing the silence
//     that used to sit here. Decompressing to scrub and re-compressing after
//     would break the byte-for-byte framing this proxy deliberately
//     preserves; asking not to compress and saying so when ignored does not.
//   - **A value shorter than minScrub is not scrubbed.** Replacing a short
//     string everywhere it occurs would corrupt far more than it protects.
//     ParseSecret warns at parse time, where the user can still choose a
//     longer credential.
//
// The replacement is length-preserving, which is not cosmetic: a terminated
// connection carries many requests, and a body whose written length disagrees
// with its declared Content-Length poisons every exchange after it on that
// connection, not just the one that was altered.
const minScrub = 8

// scrubber replaces known secret values in a byte stream, in place, keeping the
// stream's length exactly.
type scrubber struct {
	pats []scrubPat
	max  int
	// hit is called the first time a given credential is replaced, so the
	// record can say the proxy altered bytes — and which credential came back —
	// without one event per occurrence.
	hit  func(name string)
	seen map[string]bool
}

type scrubPat struct {
	name string
	v    []byte
}

// newScrubber builds one from a policy's bound secrets, or returns nil when
// there is nothing worth matching. A nil *scrubber is a no-op, so callers do
// not branch.
func newScrubber(secrets []*Secret, hit func(name string)) *scrubber {
	s := &scrubber{hit: hit, seen: map[string]bool{}}
	for _, sec := range secrets {
		v := sec.value
		if len(v) < minScrub {
			continue
		}
		s.pats = append(s.pats, scrubPat{name: sec.Name, v: []byte(v)})
		if len(v) > s.max {
			s.max = len(v)
		}
	}
	if len(s.pats) == 0 {
		return nil
	}
	return s
}

// scrub replaces every occurrence in b, in place. Returns whether anything
// changed.
func (s *scrubber) scrub(b []byte) bool {
	if s == nil {
		return false
	}
	changed := false
	for _, p := range s.pats {
		for i := 0; ; {
			j := bytes.Index(b[i:], p.v)
			if j < 0 {
				break
			}
			at := i + j
			for k := at; k < at+len(p.v); k++ {
				b[k] = '*'
			}
			i = at + len(p.v)
			changed = true
			// Once per credential per *response*, not once per occurrence: a
			// response that echoes a token forty times is one fact. The scope
			// is the response and not the connection because scrubResponse
			// builds a fresh scrubber — and so a fresh seen map — for every
			// response it handles, and a terminated connection handles many.
			// A keep-alive connection whose five responses each echo the same
			// token therefore reports five times, which is the honest count:
			// each one is a separate echo, not a repeat of the first.
			if s.hit != nil && !s.seen[p.name] {
				s.seen[p.name] = true
				s.hit(p.name)
			}
		}
	}
	return changed
}

// wrap returns a reader that scrubs what it passes through.
//
// The carry-over is the whole of the difficulty: a value can straddle two
// reads, so the last max-1 bytes of every chunk are held back until either more
// arrives or the stream ends. Without that, a credential split across a packet
// boundary passes through untouched — which is the failure a naive scrubber has
// and does not report.
func (s *scrubber) wrap(r io.ReadCloser) io.ReadCloser {
	if s == nil {
		return r
	}
	return &scrubReader{src: r, s: s}
}

type scrubReader struct {
	src  io.ReadCloser
	s    *scrubber
	buf  []byte
	eof  bool
	rerr error
}

func (r *scrubReader) Read(p []byte) (int, error) {
	for {
		// Everything except the tail that might still be the start of a match
		// is safe to hand on.
		hold := r.s.max - 1
		if r.eof {
			hold = 0
		}
		if len(r.buf) > hold {
			r.s.scrub(r.buf)
			n := copy(p, r.buf[:len(r.buf)-hold])
			r.buf = r.buf[n:]
			return n, nil
		}
		if r.eof {
			if r.rerr == nil {
				r.rerr = io.EOF
			}
			return 0, r.rerr
		}
		tmp := make([]byte, 32<<10)
		n, err := r.src.Read(tmp)
		r.buf = append(r.buf, tmp[:n]...)
		if err != nil {
			r.eof, r.rerr = true, err
		}
	}
}

func (r *scrubReader) Close() error { return r.src.Close() }

// scrubResponse replaces any bound credential a server echoed back, in the
// headers, in the body, and in the trailers, before any of it reaches the
// guest — and reports the Content-Encoding that made the body impossible to
// read when there is one, so the caller can refuse the response rather than
// deliver a body the echo suppression could not check (audit 2026-09-01, H4).
// The return is "" when the guest may have the body; a non-empty encoding
// means nothing was delivered and the caller writes a 502.
//
// Headers as well as the body because the plainest echo of all is a server
// quoting the Authorization header it rejected straight back in an error.
// Trailers because they are headers by another door (audit 2026-09-01, A4):
// a chunked response's trailer values arrive after the body and used to be
// written to the guest unexamined. They are scrubbed at body EOF, which is
// the moment the transport fills them in — before resp.Write, the only thing
// that writes them, reads the map.
//
// A body-less response — HEAD, 204, 304, http.NoBody — has no body to be
// unable to read, so it is delivered with no event whatever its
// Content-Encoding header claims. Anything else that arrives in an encoding
// this cannot match — every Content-Encoding line, every comma-separated
// coding, checked case-insensitively (L12) — is reported (OnUnscrubbable) and
// refused: the first pass passed the compressed body through and only recorded
// it, which still handed the guest a credential gzip does not hide (H4).
func (p *Proxy) scrubResponse(resp *http.Response, host string) string {
	s := newScrubber(p.Policy.secretsFor(host), func(name string) {
		if p.OnScrubbed != nil {
			p.OnScrubbed(name, host)
		}
	})
	if s == nil {
		return ""
	}
	for k, vs := range resp.Header {
		for i, v := range vs {
			b := []byte(v)
			if s.scrub(b) {
				resp.Header[k][i] = string(b)
			}
		}
	}
	// Body-less first: a HEAD/204/304 answer carrying Content-Encoding: gzip
	// leaks nothing, so it is delivered as it came with no spurious event.
	if bodyless(resp) {
		return ""
	}
	if enc := unscrubbableEncoding(resp.Header); enc != "" {
		if p.OnUnscrubbable != nil {
			p.OnUnscrubbable(host, enc)
		}
		return enc
	}
	resp.Body = &trailerScrubReader{src: s.wrap(resp.Body), resp: resp, s: s}
	return ""
}

// bodyless reports whether a response carries no body to scrub — a HEAD
// response, a 204 or 304, or an explicit http.NoBody. Such a response leaks no
// credential however it is encoded, so scrubResponse delivers it unrefused.
func bodyless(resp *http.Response) bool {
	if resp.Body == http.NoBody {
		return true
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return true
	}
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotModified:
		return true
	}
	return false
}

// unscrubbableEncoding reports the Content-Encoding that makes a response body
// impossible for the byte-based echo suppression to read, or "" when the body
// is identity or unencoded. It checks EVERY Content-Encoding header line
// (Header.Values, not Get's first) and every comma-separated coding within
// each, case-insensitively: "identity, gzip" is gzip, and a second
// "Content-Encoding: br" line after a first "identity" is br (L12). br is
// refused, not decoded — decoding it would mean a new dependency and a
// re-compress that breaks the byte-for-byte framing this proxy preserves.
func unscrubbableEncoding(h http.Header) string {
	for _, line := range h.Values("Content-Encoding") {
		for _, coding := range strings.Split(line, ",") {
			coding = strings.TrimSpace(coding)
			if coding == "" || strings.EqualFold(coding, "identity") {
				continue
			}
			return coding
		}
	}
	return ""
}

// maxRefusedEncoding bounds how much of the origin-supplied encoding name the
// refusal body repeats. An encoding token is a short word; a hostile origin's
// is whatever it likes, and this string reaches the guest.
const maxRefusedEncoding = 64

// unscrubbableRefusal is the body of the 502 a leg sends when it refuses a
// response whose encoding the echo suppression cannot read (audit 2026-09-01,
// H4). It names the host and the encoding — the encoding clipped, on a rune
// boundary — and never a header value or a body byte, which is the thing being
// withheld.
func unscrubbableRefusal(host, enc string) string {
	if len(enc) > maxRefusedEncoding {
		enc = enc[:maxRefusedEncoding]
		for len(enc) > 0 && !utf8.ValidString(enc) {
			enc = enc[:len(enc)-1]
		}
	}
	return fmt.Sprintf("kelyfos: the response from %s arrived %q-encoded, which the "+
		"credential echo suppression cannot read, so it was refused rather than "+
		"delivered unchecked", host, enc)
}

// askForIdentity replaces a request's Accept-Encoding with identity, so an
// origin with a credential bound answers uncompressed and the echo suppression
// can read the reply (audit 2026-09-01, A4/H4). Replaced, not appended:
// leaving the guest's own gzip in place would let a compliant origin still
// compress. The terminated leg and the plain-HTTP leg both call it where a
// credential is bound.
func askForIdentity(req *http.Request) {
	req.Header.Set("Accept-Encoding", "identity")
}

// trailerScrubReader scrubs the response's trailers at body EOF.
//
// The transport fills resp.Trailer as the body is consumed, so the values do
// not exist until the read that ends the body; scrubbing there is the only
// moment they can be caught, and it is before resp.Write writes them — resp.Write
// copies the body to EOF and only then reads the trailer map to write it.
type trailerScrubReader struct {
	src      io.ReadCloser
	resp     *http.Response
	s        *scrubber
	scrubbed bool
}

func (r *trailerScrubReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if err == io.EOF && !r.scrubbed {
		r.scrubbed = true
		for k, vs := range r.resp.Trailer {
			for i, v := range vs {
				b := []byte(v)
				if r.s.scrub(b) {
					r.resp.Trailer[k][i] = string(b)
				}
			}
		}
	}
	return n, err
}

func (r *trailerScrubReader) Close() error { return r.src.Close() }
