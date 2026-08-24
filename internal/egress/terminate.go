package egress

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// terminate handles a CONNECT to a domain that has a secret bound to it.
//
// This is the one case where the proxy decrypts. It presents a certificate
// minted by the per-run CA, reads the guest's requests, attaches the credential,
// and forwards them over a properly validated TLS connection to the real server.
// The guest never holds the secret, and the proxy never holds it for a domain
// nobody bound one to.
//
// Everything about it is recorded as mode=terminated, so a user can always tell
// which traffic the proxy was able to read (decision D6).
func (p *Proxy) terminate(client net.Conn, host string, port int, bound []*Secret) {
	if p.CA == nil {
		p.report(Attempt{Host: host, Port: port, Reason: ReasonBadRequest})
		writeStatus(client, http.StatusInternalServerError, "kelyfos: no CA for TLS termination")
		return
	}
	leaf, err := p.CA.leafFor(host)
	if err != nil {
		p.report(Attempt{Host: host, Port: port, Reason: ReasonBadRequest})
		writeStatus(client, http.StatusInternalServerError, "kelyfos: "+err.Error())
		return
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	inner := tls.Server(client, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err := inner.Handshake(); err != nil {
		// Almost always a client that pins certificates, which termination
		// breaks by design. Say so rather than leaving a bare TLS error.
		p.report(Attempt{Host: host, Port: port, Reason: ReasonPinned})
		return
	}
	defer inner.Close()

	upstreamAddr := net.JoinHostPort(host, strconv.Itoa(port))
	br := bufio.NewReader(inner)
	var in, out int64

	// A single TLS connection carries many requests when keep-alive is in play,
	// and each one needs the credential.
	for {
		var attached *Secret
		req, err := http.ReadRequest(br)
		if err != nil {
			if !errors.Is(err, io.EOF) && in == 0 && out == 0 {
				p.report(Attempt{Host: host, Port: port, Reason: ReasonBadRequest})
				return
			}
			break
		}
		req.URL.Scheme = "https"
		req.URL.Host = upstreamAddr
		req.RequestURI = ""

		// The credential goes only to the host this connection was opened,
		// verified and recorded against.
		//
		// This is not a new rule, it is a defect being closed. http.ReadRequest
		// fills req.Host from the guest's own Host: header, and Go's
		// Request.write prefers req.Host over req.URL.Host — so setting the URL
		// host above does not change the header on the wire. A guest could
		// CONNECT to a bound domain, get the certificate for it, and then
		// address the credentialed request to any other name it liked:
		//
		//	dialled and TLS-verified : api.github.com:443   (the bound host)
		//	Host: on the wire        : whatever it chose
		//
		// On a virtual-hosted or shared-edge origin that routes on Host, the
		// bound credential is then presented to a different site — and the
		// record named the CONNECT target, so it said the wrong thing too.
		// Measured against Go's own Request.write before being written down.
		//
		// Withheld rather than rewritten: rewriting a guest's Host header would
		// silently change what it asked for, and the request itself is allowed
		// — `allow` decided that. What is refused is the credential.
		secret, why := pick(bound, req, host)
		if secret != nil {
			req.Header.Set("Authorization", secret.Header())
			attached = secret
		} else if len(bound) > 0 && p.OnWithheld != nil {
			// Say so. A credential that silently does not attach sends the
			// request out unauthenticated and the only symptom is a failure
			// from somewhere else.
			p.OnWithheld(bound[0].Name, host, why)
		}

		resp, err := p.upstream().RoundTrip(req)
		if err != nil {
			writeStatus(inner, http.StatusBadGateway, "kelyfos: "+err.Error())
			p.report(Attempt{Host: host, Port: port, Reason: ReasonDialFailed})
			return
		}
		if attached != nil && p.OnSecret != nil {
			p.OnSecret(attached.Name, host)
		}
		p.scrubResponse(resp, host)
		// A chunked body reports -1, which is not a byte count. Adding it
		// walked the receipt backwards; an unknown length contributes nothing
		// rather than subtracting (F-D33).
		if req.ContentLength > 0 {
			out += req.ContentLength
		}
		if resp.ContentLength > 0 {
			in += resp.ContentLength
		}
		// A response whose length is indeterminate is framed by the connection
		// closing, so the loop must not carry on waiting for another request:
		// the client would sit there until its own timeout with the whole body
		// already in hand.
		indeterminate := resp.ContentLength < 0 && resp.TransferEncoding == nil
		werr := resp.Write(activeWriter{inner, p})
		resp.Body.Close()
		if werr != nil || indeterminate || resp.Close || req.Close {
			break
		}
	}

	p.report(Attempt{
		Host: host, Port: port, Allowed: true, Mode: ModeTerminated,
		BytesIn: in, BytesOut: out,
	})
}

// terminatedTransport is the upstream leg for terminated connections.
//
// Compression is disabled deliberately. Go's default transport adds
// "Accept-Encoding: gzip" and transparently decompresses the reply, which is
// convenient for a client and wrong for a proxy: it discards the original
// Content-Length and leaves a response that can only be framed by closing the
// connection. Passing bytes through as the server sent them keeps the framing
// the client expects — and keeps keep-alive working.
var terminatedTransport = &http.Transport{
	DisableCompression:  true,
	ForceAttemptHTTP2:   false,
	MaxIdleConnsPerHost: 4,
	TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
}

func (p *Proxy) upstream() http.RoundTripper {
	if p.Upstream != nil {
		return p.Upstream
	}
	return terminatedTransport
}

// sameHost reports whether a request's Host header names the host the
// connection was opened to. An empty Host is fine: Go then falls back to
// req.URL.Host, which is the CONNECT target itself.
func sameHost(reqHost, bound string) bool {
	if reqHost == "" {
		return true
	}
	h := reqHost
	if only, _, err := net.SplitHostPort(h); err == nil {
		h = only
	}
	return strings.ToLower(strings.TrimRight(h, ".")) == bound
}

// pick chooses which bound credential, if any, may be attached to one request,
// and says why when none may.
//
// Declaration order decides between two secrets that both cover a request: the
// policy file is read top to bottom and the first binding that fits wins, which
// is the rule a person can predict without knowing how prefixes compare.
func pick(bound []*Secret, req *http.Request, host string) (*Secret, string) {
	// The host check comes first and applies to all of them: a request that
	// addresses another name is not inside anybody's scope.
	if !sameHost(req.Host, host) {
		return nil, WithheldHostMismatch
	}
	why := ""
	for _, s := range bound {
		if ok, reason := s.Scope.covers(req); ok {
			return s, ""
		} else if why == "" {
			why = reason
		}
	}
	return nil, why
}
