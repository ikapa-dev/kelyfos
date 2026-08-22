package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// CA is the per-run certificate authority the proxy uses to terminate TLS for
// domains that have a secret bound to them (decision D6).
//
// It is generated fresh for every sandbox, lives only in this process's memory,
// and is never written to disk. Only the trust anchor — the certificate, never
// the key — crosses into the guest, and it stops being worth anything the moment
// the run ends. That is deliberate: a CA that persists is a CA that can be
// stolen once and used forever, and this one exists solely so a proxy can read
// traffic on the same machine that created it.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// NewCA mints an authority for one run.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "KelyfOS egress CA (ephemeral)",
			Organization: []string{"KelyfOS"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		// Short-lived by construction. A sandbox does not outlive a day, and a
		// certificate that cannot outlive its purpose cannot be misused later.
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:   cert,
		key:    key,
		pem:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves: map[string]*tls.Certificate{},
	}, nil
}

// AnchorPEM is the certificate the guest is asked to trust. The private key
// never leaves this process, so possessing this proves nothing and signs
// nothing.
func (c *CA) AnchorPEM() []byte { return c.pem }

// leafFor mints, and caches, a server certificate for one host.
func (c *CA) leafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if tc, ok := c.leaves[host]; ok {
		return tc, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// A certificate with a DNS name in it does not validate for a connection
	// made to an address. Callers reach hosts by name in practice, but a
	// literal address is legal in a CONNECT and must not fail obscurely.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	c.leaves[host] = tc
	return tc, nil
}
