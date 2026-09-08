package config

import (
	"os"
	"path/filepath"
	"testing"
)

// D101: a discovered policy's secrets are honoured only once the file, at its
// current contents, is in the per-user record.

func writePolicy(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, FileName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestD101_TrustIsBoundToPathAndContents(t *testing.T) {
	root := t.TempDir()
	dir := t.TempDir()
	p := writePolicy(t, dir, "[sandbox]\nallow = [\"a.example\"]\nsecrets = [\"T@a.example\"]\n")

	if ok, err := SecretsTrusted(root, p); err != nil || ok {
		t.Fatalf("a file nobody approved reads as trusted: ok=%v err=%v", ok, err)
	}
	if _, err := TrustSecrets(root, p); err != nil {
		t.Fatal(err)
	}
	if ok, err := SecretsTrusted(root, p); err != nil || !ok {
		t.Fatalf("an approved file is not trusted: ok=%v err=%v", ok, err)
	}
	// The record binds the contents: an edit lapses the approval.
	writePolicy(t, dir, "[sandbox]\nallow = [\"b.example\"]\nsecrets = [\"T@b.example\"]\n")
	if ok, _ := SecretsTrusted(root, p); ok {
		t.Fatal("a changed file is still trusted")
	}
	// And the path: the same bytes elsewhere are a different file.
	other := writePolicy(t, t.TempDir(), "[sandbox]\nallow = [\"a.example\"]\nsecrets = [\"T@a.example\"]\n")
	if ok, _ := SecretsTrusted(root, other); ok {
		t.Fatal("the same contents at another path read as trusted")
	}
}

func TestD101_RevokeAndListAndFileMode(t *testing.T) {
	root := t.TempDir()
	p := writePolicy(t, t.TempDir(), "[sandbox]\nsecrets = [\"T@a.example\"]\nallow = [\"a.example\"]\n")
	if _, err := TrustSecrets(root, p); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustSecrets(root, p); err != nil { // idempotent: one entry per path
		t.Fatal(err)
	}
	list, err := TrustedSecretPolicies(root)
	if err != nil || len(list) != 1 {
		t.Fatalf("want one entry, got %d (err %v)", len(list), err)
	}
	info, err := os.Stat(SecretTrustFile(root))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the record is mode %04o, want 0600", info.Mode().Perm())
	}
	found, err := RevokeSecretTrust(root, p)
	if err != nil || !found {
		t.Fatalf("revoke: found=%v err=%v", found, err)
	}
	if ok, _ := SecretsTrusted(root, p); ok {
		t.Fatal("a revoked file is still trusted")
	}
	if found, _ := RevokeSecretTrust(root, p); found {
		t.Fatal("a second revoke found an entry")
	}
}

func TestD101_AnUnreadableRecordIsAnErrorNotANo(t *testing.T) {
	root := t.TempDir()
	p := writePolicy(t, t.TempDir(), "[sandbox]\nsecrets = [\"T@a.example\"]\nallow = [\"a.example\"]\n")
	if err := os.MkdirAll(filepath.Dir(SecretTrustFile(root)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SecretTrustFile(root), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SecretsTrusted(root, p); err == nil {
		t.Fatal("a corrupt record answered rather than erred")
	}
}

func TestD101_DeclaresSecretsSeesTeamAgents(t *testing.T) {
	var none *Config
	if none.DeclaresSecrets() {
		t.Fatal("nil declares secrets")
	}
	c := &Config{}
	if c.DeclaresSecrets() {
		t.Fatal("an empty policy declares secrets")
	}
	c.Team = &Team{Agents: []TeamAgent{{Name: "a"}, {Name: "b", Secrets: []string{"T@x.example"}}}}
	if !c.DeclaresSecrets() {
		t.Fatal("a team agent's secrets are not seen")
	}
}
