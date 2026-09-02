package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The audit of 2026-09-01's A17: on a machine with cgroup v2 but no
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

// A systemd-run that answers and fails — no bus — is a different diagnosis
// from the hang, and it must not be told it timed out. Its first stderr line
// is quoted onto the operator's terminal (a CSI escape and all), only the
// first line survives, and the refusal is instant rather than paced by the 4 s
// bound the hang is.
func TestTheSystemdScopePreflightRefusesABrokenOne(t *testing.T) {
	// printf, not echo: the ESC (\033) and the newline have to be the bytes
	// they name regardless of which /bin/sh the runner has.
	stubSystemdRun(t, "#!/bin/sh\nprintf 'Failed to connect to bus\\033[K\\na second diagnostic line\\n' >&2\nexit 1\n")
	started := time.Now()
	err := preflightSystemdScope("kelyfos-preflight-test-broken")
	took := time.Since(started)
	if err == nil {
		t.Fatal("a systemd-run that fails was accepted; the boot would hang later")
	}
	// The first line, quoted — the ESC rendered \x1b, never replayed raw.
	if !strings.Contains(err.Error(), `failed: "Failed to connect to bus\x1b[K"`) {
		t.Errorf("the refusal does not carry the quoted first stderr line:\n%v", err)
	}
	if strings.Contains(err.Error(), "did not complete within") {
		t.Errorf("an instant failure is misdiagnosed as a timeout:\n%v", err)
	}
	if strings.Contains(err.Error(), "second diagnostic line") {
		t.Errorf("the refusal replayed more than the first stderr line:\n%v", err)
	}
	if took > 2*time.Second {
		t.Errorf("a failing systemd-run took %s to refuse; it answered and should be instant", took)
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
	if strings.Contains(err.Error(), "failed:") {
		t.Errorf("a hang is misdiagnosed as an answered failure:\n%v", err)
	}
}
