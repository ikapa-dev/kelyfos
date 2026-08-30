package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/recorder"
)

func signingKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A signature covers the record, not the page.
//
// This is the property that makes re-exporting the same session produce the same
// signature: the page carries a generation timestamp, so signing the page would
// make two honest exports of one record disagree, and a reader comparing them
// would be looking at a difference that means nothing.
func TestASignatureSurvivesReExport(t *testing.T) {
	chain := chainOf(t, []recorder.Event{
		ev(recorder.TypeSessionStart, ""),
		ev(recorder.TypeSessionEnd, ""),
	})
	key := signingKey(t)

	var first, second bytes.Buffer
	if _, err := RenderSigned(&first, "s1", chain, key); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderSigned(&second, "s1", chain, key); err != nil {
		t.Fatal(err)
	}
	a, b := SignatureIn(first.Bytes()), SignatureIn(second.Bytes())
	if a.Sig == "" {
		t.Fatal("the signed export carries no signature")
	}
	if a.Sig != b.Sig {
		t.Error("two exports of one record produced different signatures")
	}
	if a.Key != b.Key {
		t.Error("two exports of one record named different keys")
	}
}

// The signature is checked against the record, so editing either breaks it.
func TestASignatureIsAboutThisRecordAndThisKey(t *testing.T) {
	chain := chainOf(t, []recorder.Event{ev(recorder.TypeSessionStart, "")})
	_, head, err := recorder.Verify(bytes.NewReader(chain))
	if err != nil {
		t.Fatal(err)
	}
	key := signingKey(t)
	sig, err := SignChain(chain, head, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sig.Check(chain, head); err != nil {
		t.Fatalf("an untouched record failed its own signature: %v", err)
	}

	// A different record.
	other := chainOf(t, []recorder.Event{ev(recorder.TypeSessionEnd, "")})
	_, otherHead, _ := recorder.Verify(bytes.NewReader(other))
	if _, err := sig.Check(other, otherHead); err == nil {
		t.Error("a signature verified against a record it was not made over")
	}
	// The same record, a different head.
	if _, err := sig.Check(chain, strings.Repeat("9", 64)); err == nil {
		t.Error("a signature verified against a head it was not made over")
	}
	// A different key claiming the same signature.
	forged := sig
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	forged.Key = PublicKeyHex(pub)
	if _, err := forged.Check(chain, head); err == nil {
		t.Error("a signature verified under a key that did not make it")
	}
}

// An unsigned report is an ordinary report. The signature is optional by
// construction, and nothing may drift into requiring one.
func TestAnUnsignedReportIsStillAReport(t *testing.T) {
	chain := chainOf(t, []recorder.Event{ev(recorder.TypeSessionStart, "")})
	var buf bytes.Buffer
	if _, err := Render(&buf, "s1", chain); err != nil {
		t.Fatal(err)
	}
	page := buf.Bytes()
	if sig := SignatureIn(page); sig.Sig != "" || sig.Key != "" {
		t.Error("an unsigned export carries a signature")
	}
	if got, err := ExtractChain(page); err != nil || !bytes.Equal(got, chain) {
		t.Errorf("an unsigned export did not carry its record: %v", err)
	}
	for _, unwanted := range []string{"Signed by the key", "unsigned"} {
		if bytes.Contains(page, []byte(unwanted)) {
			t.Errorf("an unsigned page says %q about itself", unwanted)
		}
	}
}

// A record that does not verify is not signed at all. A signature over a broken
// chain is a statement about nothing that still reads as a statement.
func TestABrokenRecordIsNotSigned(t *testing.T) {
	chain := chainOf(t, []recorder.Event{
		ev(recorder.TypeSessionStart, ""),
		ev(recorder.TypeSessionEnd, ""),
	})
	broken := bytes.Replace(chain, []byte(`"source":"host"`), []byte(`"source":"gues"`), 1)
	var buf bytes.Buffer
	if _, err := RenderSigned(&buf, "s1", broken, signingKey(t)); err == nil {
		t.Error("a broken record was signed")
	}
}

// The key loader takes what openssl writes, which is the point of choosing
// PKCS#8: a person needs no tool this project ships to make a key whose whole
// value is that it is theirs.
func TestTheKeyLoaderRefusesWhatIsNotAKey(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"not-pem.txt":   "just some text\n",
		"empty.pem":     "",
		"wrong-pem.pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSigningKey(p); err == nil {
			t.Errorf("%s was accepted as a signing key", name)
		}
	}
	if _, err := LoadSigningKey(filepath.Join(dir, "absent")); err == nil {
		t.Error("a missing file was accepted as a signing key")
	}
}
