package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "image.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCheckManifestAcceptsMatch(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `{"schema":1,"arch":"x86_64","flavor":"dev"}`)
	if err := checkManifest(dir, "x86_64", "dev"); err != nil {
		t.Fatalf("matching manifest rejected: %v", err)
	}
}

// The bug D21 exists for: booting one flavor while recording another.
func TestCheckManifestRejectsFlavorMismatch(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `{"schema":1,"arch":"x86_64","flavor":"base"}`)
	err := checkManifest(dir, "x86_64", "dev")
	if err == nil {
		t.Fatal("booted the base image while the caller asked for dev — this is the mislabelling bug")
	}
	// The message has to name both flavors, or the user cannot act on it.
	for _, want := range []string{"dev", "base"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestCheckManifestRejectsArchMismatch(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `{"schema":1,"arch":"aarch64","flavor":"dev"}`)
	if err := checkManifest(dir, "x86_64", "dev"); err == nil {
		t.Fatal("accepted an aarch64 image for an x86_64 sandbox")
	}
}

// A missing manifest must fail loudly. A silent pass is how the original bug
// went unnoticed, so the absence of the check must not be re-introduced as a
// fallback.
func TestCheckManifestRejectsMissing(t *testing.T) {
	err := checkManifest(t.TempDir(), "x86_64", "dev")
	if err == nil {
		t.Fatal("missing image.json accepted")
	}
	if !strings.Contains(err.Error(), "make image") && !strings.Contains(err.Error(), "fetch-image") {
		t.Errorf("error %q does not tell the user how to fix it", err)
	}
}

func TestCheckManifestRejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, `not json at all`)
	if err := checkManifest(dir, "x86_64", "dev"); err == nil {
		t.Fatal("accepted a corrupt manifest")
	}
}
