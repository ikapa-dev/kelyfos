package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The audit of 2026-09-01's A6: `allow = ["org"]` in kelyfos.toml was a
// whole-TLD grant accepted silently at load. It is refused at parse time now,
// with the file and the entry named.
func TestABareTLDAllowEntryIsRefusedAtLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	body := "[sandbox]\nimage = \"dev\"\nallow = [\"org\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("a whole-TLD allowlist loaded cleanly")
	}
	for _, want := range []string{"org", "bare top-level domain", "[allow.single_label]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// A real host loads.
	body = "[sandbox]\nimage = \"dev\"\nallow = [\"example.org\"]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a reasonable allowlist was refused: %v", err)
	}
}
