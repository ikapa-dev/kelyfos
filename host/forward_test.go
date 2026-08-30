package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
)

func TestForwardSpecShapes(t *testing.T) {
	f, err := parseForwardSpec("8080:80")
	if err != nil || f.Host != 8080 || f.Guest != 80 {
		t.Errorf("8080:80 = %+v, %v", f, err)
	}
	for _, bad := range []string{"8080", "8080:", ":80", "http:80", "8080:https",
		"0:80", "8080:0", "70000:80", "8080:70000", ""} {
		if _, err := parseForwardSpec(bad); err == nil {
			t.Errorf("-p %q was accepted", bad)
		}
	}
	// The shape is in the message, because somebody who typed it wrong is
	// looking at the message rather than at the manual.
	_, err = parseForwardSpec("8080")
	if err == nil || !strings.Contains(err.Error(), "host:guest") {
		t.Errorf("the refusal does not say the shape: %v", err)
	}
}

// A -p on the command line replaces the file's list rather than adding to it,
// the way --allow already does. Otherwise "forward only this one" cannot be
// said without editing the file.
func TestFlagsReplaceTheFilesForwards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kelyfos.toml")
	body := "[[forward]]\nhost = 8080\nguest = 80\n\n[[forward]]\nhost = 5433\nguest = 5432\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}

	fromFile, err := resolveForwards(nil, cfg)
	if err != nil || len(fromFile) != 2 {
		t.Fatalf("the file's forwards = %+v, %v", fromFile, err)
	}
	fromFlags, err := resolveForwards([]string{"9090:90"}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromFlags) != 1 || fromFlags[0].Host != 9090 {
		t.Errorf("a -p did not replace the file's list: %+v", fromFlags)
	}
}

// One host port carries one guest port. Two flags claiming the same host port
// have no correct interpretation, so neither is picked.
func TestOneHostPortCarriesOneGuestPort(t *testing.T) {
	_, err := resolveForwards([]string{"8080:80", "8080:81"}, nil)
	if err == nil {
		t.Fatal("a doubly-claimed host port was accepted")
	}
	if !strings.Contains(err.Error(), "already forwarded") {
		t.Errorf("%v", err)
	}
}

// No policy file is not an error: a run with -p and no kelyfos.toml forwards
// exactly what the flags say.
func TestForwardsWithoutAPolicyFile(t *testing.T) {
	got, err := resolveForwards([]string{"8080:80"}, nil)
	if err != nil || len(got) != 1 || got[0].Guest != 80 {
		t.Errorf("got %+v, %v", got, err)
	}
	if got, err := resolveForwards(nil, nil); err != nil || len(got) != 0 {
		t.Errorf("no flags and no file should forward nothing: %+v, %v", got, err)
	}
}
