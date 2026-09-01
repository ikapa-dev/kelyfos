package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The audit of 2026-09-01's A17b: on a machine with cgroup v2 but no
// delegation and no working user systemd session, --cpu-quota used to hang
// the boot after session.start with no refusal and no output. The preflight
// is what turns that into a named refusal, and these tests hold it — without
// assuming anything about the machine they run on, since CI lands in a
// container and the dev VM has delegation. What is under test is the
// preflight's own contract: it passes a working systemd-run, and refuses a
// broken or hung one, inside its bound.

// stubSystemdRun writes a fake systemd-run into a directory on PATH. The
// argument behaviour is the preflight's: `--unit NAME -- true` is the throwaway
// scope it must be able to run.
func stubSystemdRun(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestTheSystemdScopePreflightAcceptsAWorkingSystemdRun(t *testing.T) {
	stubSystemdRun(t, "#!/bin/sh\nexit 0\n")
	if err := preflightSystemdScope("kelyfos-preflight-test-ok"); err != nil {
		t.Fatalf("a working systemd-run was refused: %v", err)
	}
}

func TestTheSystemdScopePreflightRefusesABrokenOne(t *testing.T) {
	stubSystemdRun(t, "#!/bin/sh\necho 'no user session' >&2\nexit 1\n")
	err := preflightSystemdScope("kelyfos-preflight-test-broken")
	if err == nil {
		t.Fatal("a systemd-run that fails was accepted; the boot would hang later")
	}
	for _, want := range []string{"cannot apply a CPU quota", "drop --cpu-quota"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q:\n%v", want, err)
		}
	}
}

// The heart of the finding: the hang. A systemd-run that never answers must
// cost a refusal inside the preflight bound, not a boot that waits forever.
// The stub execs its sleeper, so the context kill hits it directly rather
// than leaving an orphan holding the output pipe — the one shape the real
// systemd-run hang takes that a naive kill does not unblock.
func TestTheSystemdScopePreflightTimesOutAndSaysSo(t *testing.T) {
	stubSystemdRun(t, "#!/bin/sh\nexec sleep 300\n")
	started := time.Now()
	err := preflightSystemdScope("kelyfos-preflight-test-hang")
	took := time.Since(started)
	if err == nil {
		t.Fatal("a hung systemd-run was accepted")
	}
	if took > systemdScopePreflightTimeout+2*time.Second {
		t.Errorf("the preflight took %s, want it bounded near %s", took, systemdScopePreflightTimeout)
	}
	if !strings.Contains(err.Error(), "did not complete within") {
		t.Errorf("the refusal does not name the bound:\n%v", err)
	}
}
