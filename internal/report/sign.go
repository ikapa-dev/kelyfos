package report

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Signing an export, and the one claim it adds (P6-7).
//
// The chain already proves that no line was altered and none removed from the
// beginning or the middle. What it cannot prove is *who exported it*: anyone who
// can write the file can rewrite it end to end and recompute every digest, and a
// record cut short at its end verifies. A signature is the answer to both, and
// only if the key is one the reader can anchor.
//
// So the key is the user's. `--sign-key` takes an ed25519 private key the person
// already has, ed25519 comes from the standard library, and nothing new is
// depended on. A per-run ephemeral key is refused rather than offered: it proves
// one process made both halves, which the chain already proves, and a page
// saying "signed" beside a key nobody has ever seen invites a reader to stop
// asking — which is the badge P6-6 removed, wearing a different hat.
//
// **An unsigned report still verifies.** The signature is optional by
// construction: `kelyfos verify` reports a vocabulary — the chain intact or
// broken, crossed with signed-by-K or unsigned — rather than a verdict, so
// nothing can drift into treating "unsigned" as "bad" or "signed" as "fine".

// signaturePreimage is exactly what a signature covers.
//
// The chain head and a digest of the record, and nothing else. Not the rendered
// page: the page carries a generation timestamp, so signing it would mean a
// re-export of the same session produced a different signature, and a reader
// comparing two honest exports would find them disagreeing. Not the timestamp,
// for the same reason. What is signed is the evidence, which is the thing that
// does not change.
//
// The version tag is first so that a future format cannot be verified as this
// one by a build that only knows this one.
func signaturePreimage(chain []byte, head string) []byte {
	sum := sha256.Sum256(chain)
	return fmt.Appendf(nil, "kelyfos-report-signature-v1\n%s\n%s\n", head, hex.EncodeToString(sum[:]))
}

// Signature is what a page carries about who exported it.
type Signature struct {
	Sig string // hex, ed25519 over signaturePreimage
	Key string // hex, the ed25519 public key that made it
}

// Fingerprint is how a reader refers to a key without pasting it.
//
// It is a digest of the public key rather than the key itself, because what a
// reader does with this is compare it against one they were given somewhere
// else, and a 64-character hex string is already more than anybody reads
// carefully.
func (s Signature) Fingerprint() string {
	if s.Key == "" {
		return ""
	}
	raw, err := hex.DecodeString(s.Key)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// SignChain signs a record with a key the user holds.
func SignChain(chain []byte, head string, key ed25519.PrivateKey) (Signature, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Signature{}, errors.New("that is not an ed25519 private key")
	}
	sig := ed25519.Sign(key, signaturePreimage(chain, head))
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return Signature{}, errors.New("the key has no ed25519 public half")
	}
	return Signature{Sig: hex.EncodeToString(sig), Key: hex.EncodeToString(pub)}, nil
}

// CheckSignature reports whether a signature is the one this record would have.
//
// It answers a narrow question and the caller has to know which: that these
// bytes were signed by the holder of *this* key. Whether that key is anybody the
// reader should believe is a question no file can answer about itself.
func (s Signature) Check(chain []byte, head string) (ed25519.PublicKey, error) {
	if s.Sig == "" || s.Key == "" {
		return nil, errors.New("this report carries no signature")
	}
	sig, err := hex.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("the signature in this report is not readable: %w", err)
	}
	rawKey, err := hex.DecodeString(s.Key)
	if err != nil {
		return nil, fmt.Errorf("the signing key in this report is not readable: %w", err)
	}
	if len(rawKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("the signing key in this report is %d bytes, not %d",
			len(rawKey), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(rawKey)
	if !ed25519.Verify(pub, signaturePreimage(chain, head), sig) {
		return nil, errors.New("the signature does not match this record and this key")
	}
	return pub, nil
}

// SignatureIn reads what a page says about who signed it.
func SignatureIn(page []byte) Signature {
	return Signature{
		Sig: marked(page, "kelyfos-signature"),
		Key: marked(page, "kelyfos-signing-key"),
	}
}

// LoadSigningKey reads a PEM PKCS#8 ed25519 private key.
//
// PKCS#8 because that is what `openssl genpkey -algorithm ed25519` writes, so a
// person needs no tool this project ships to make one — which matters for a key
// whose whole value is that it is theirs and not ours.
func LoadSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file; make one with: "+
			"openssl genpkey -algorithm ed25519 -out kelyfos-signing.key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s does not hold a PKCS#8 private key: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T; KelyfOS signs with ed25519, which is small, "+
			"has no parameters to get wrong, and is in the standard library", path, parsed)
	}
	return key, nil
}

// LoadAnchorKey reads a public key the *reader* holds, so a report can be
// checked against a key it did not supply itself.
//
// Both shapes a person is likely to have: the PEM a `openssl pkey -pubout`
// produces, and the bare hex this product prints.
func LoadAnchorKey(pathOrHex string) (ed25519.PublicKey, error) {
	if raw, err := hex.DecodeString(pathOrHex); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	raw, err := os.ReadFile(pathOrHex)
	if err != nil {
		return nil, fmt.Errorf("%q is neither an ed25519 public key in hex nor a file: %w", pathOrHex, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM file", pathOrHex)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s does not hold a public key: %w", pathOrHex, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s holds a %T, not an ed25519 public key", pathOrHex, parsed)
	}
	return pub, nil
}

// PublicKeyHex is how this product prints a key for somebody to write down.
func PublicKeyHex(pub crypto.PublicKey) string {
	k, ok := pub.(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return hex.EncodeToString(k)
}
