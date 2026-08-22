package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// trustAnchorPath is where the egress CA's certificate lands. It is in the
// overlay, not the image: the CA is minted per run and never persisted, so
// baking one into the rootfs would be baking in a certificate that is wrong for
// every run but the one that made it (decision D6).
const trustAnchorPath = "/etc/ssl/certs/kelyfos-egress-ca.pem"

// installTrustAnchor writes the proxy's CA certificate and points every TLS
// library KelyfOS can reach at it.
//
// The environment variables are the whole reason this works. A guest that only
// updated the system trust store would still be defeated by Python, whose
// requests library ships its own CA bundle in certifi, and by Node, which
// carries its own roots — both ignore the system store entirely. KelyfOS owns
// the guest's default environment (docs/protocol.md §5.2), so it can point all
// of them at one file; on a general-purpose machine this would not be possible,
// which is exactly why decision D6 chose termination here and would not
// elsewhere.
func installTrustAnchor(pemData string) error {
	if strings.TrimSpace(pemData) == "" {
		return errors.New("trust: empty certificate")
	}
	if !strings.Contains(pemData, "BEGIN CERTIFICATE") {
		return errors.New("trust: not a PEM certificate")
	}
	if err := os.MkdirAll(filepath.Dir(trustAnchorPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(trustAnchorPath, []byte(pemData), 0o644); err != nil {
		return err
	}

	// Append to the distribution bundle too, so anything that reads the system
	// store keeps working alongside the variables below.
	for _, bundle := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"} {
		if f, err := os.OpenFile(bundle, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			_, _ = f.WriteString("\n" + pemData)
			_ = f.Close()
		}
	}

	defaultEnv = append(defaultEnv,
		"SSL_CERT_FILE="+trustAnchorPath,       // OpenSSL, and most C programs
		"CURL_CA_BUNDLE="+trustAnchorPath,      // curl
		"REQUESTS_CA_BUNDLE="+trustAnchorPath,  // Python requests, which ignores the system store
		"NODE_EXTRA_CA_CERTS="+trustAnchorPath, // Node, which carries its own roots
		"GIT_SSL_CAINFO="+trustAnchorPath,      // git over HTTPS
	)
	logf("egress CA installed at %s", trustAnchorPath)
	return nil
}
