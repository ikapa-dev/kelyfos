package egress

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
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
func (p *Proxy) terminate(client net.Conn, host string, port int, secret *Secret) {
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
		req.Header.Set("Authorization", secret.Header())

		resp, err := p.upstream().RoundTrip(req)
		if err != nil {
			writeStatus(inner, http.StatusBadGateway, "kelyfos: "+err.Error())
			p.report(Attempt{Host: host, Port: port, Reason: ReasonDialFailed})
			return
		}
		if p.OnSecret != nil {
			p.OnSecret(secret.Name, host)
		}
		out += req.ContentLength
		if resp.ContentLength > 0 {
			in += resp.ContentLength
		}
		if err := resp.Write(inner); err != nil {
			resp.Body.Close()
			break
		}
		resp.Body.Close()
		if resp.Close || req.Close {
			break
		}
	}

	p.report(Attempt{
		Host: host, Port: port, Allowed: true, Mode: ModeTerminated,
		BytesIn: in, BytesOut: out,
	})
}

func (p *Proxy) upstream() http.RoundTripper {
	if p.Upstream != nil {
		return p.Upstream
	}
	return http.DefaultTransport
}
