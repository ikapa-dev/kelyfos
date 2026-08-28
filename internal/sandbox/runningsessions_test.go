package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeRunningState is RunningSessions' own test fixture: a sandbox.json
// under this id's run directory, the shape `New` writes for a real machine.
func writeRunningState(t *testing.T, st State) {
	t.Helper()
	dir := RunDirOf(st.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// RunDir is what readState checks the file's own location against, and the
	// state a real machine writes always carries it (F19).
	st.RunDir = dir
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	// Beside the chroot rather than inside it — where writeState puts it, and
	// where readState looks.
	if err := os.WriteFile(filepath.Join(stateDir(dir), stateFile), blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunningSessionsNoRunRoot is the "nothing has ever run here" case —
// RunRoot()/firecracker does not exist at all, which must read as no live
// sessions rather than an error.
func TestRunningSessionsNoRunRoot(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	live, err := RunningSessions()
	if err != nil {
		t.Fatalf("RunningSessions: %v", err)
	}
	if len(live) != 0 {
		t.Errorf("live = %v, want empty with no run root at all", live)
	}
}

// TestRunningSessionsFindsAnOrdinarySandbox is the base case: a sandbox
// whose own id names its run directory, and whose Session is empty —
// RecordSession() falls back to ID (sandbox.go's own rule) — is found
// under its own id.
func TestRunningSessionsFindsAnOrdinarySandbox(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRunningState(t, State{ID: "solo-sandbox", PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})

	live, err := RunningSessions()
	if err != nil {
		t.Fatalf("RunningSessions: %v", err)
	}
	if !live["solo-sandbox"] {
		t.Errorf("live = %v, want solo-sandbox present", live)
	}
}

// TestRunningSessionsFindsATeamMemberByItsChain is P7-5's own reason this
// function exists (B1): a team member's own sandbox id is not the team's
// chain id, but its State.Session names that chain — the same wiring
// host/team.go's raiseTeam gives a real member. RunningSessions must
// report the CHAIN id as live, not the member's own id, since that chain
// id is what `kelyfos sessions erase` would be asked to touch.
func TestRunningSessionsFindsATeamMemberByItsChain(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeRunningState(t, State{ID: "member-own-id", Session: "team-chain-id",
		PID: os.Getpid(), Arch: "aarch64", Flavor: "dev"})

	live, err := RunningSessions()
	if err != nil {
		t.Fatalf("RunningSessions: %v", err)
	}
	if !live["team-chain-id"] {
		t.Errorf("live = %v, want team-chain-id present (from the member's own Session field)", live)
	}
	if live["member-own-id"] {
		t.Errorf("live = %v, want member-own-id itself absent — it is not a chain id anything opens", live)
	}
}

// TestRunningSessionsIgnoresADeadPID is the other half of Load's own
// aliveness check, reused here: a leftover run directory from a crash — a
// sandbox.json whose PID nothing still answers to — must not read as live,
// or a crash would permanently block erasing the session it crashed out of.
func TestRunningSessionsIgnoresADeadPID(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	// PID 0 is never a real process; alive() (sandbox.go) treats it, and any
	// PID this test cannot plausibly be running as, as not alive.
	writeRunningState(t, State{ID: "crashed-sandbox", PID: 0, Arch: "aarch64", Flavor: "dev"})

	live, err := RunningSessions()
	if err != nil {
		t.Fatalf("RunningSessions: %v", err)
	}
	if live["crashed-sandbox"] {
		t.Errorf("live = %v, want a dead PID's own sandbox absent", live)
	}
}
