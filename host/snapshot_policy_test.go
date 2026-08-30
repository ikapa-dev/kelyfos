package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// F9: `kelyfos snapshot restore` reads no policy file, unlike run, fork and
// the identical operation through serve-mcp (sandbox_restore). These tests
// cover the three pieces that close that gap — checkSnapshotCeiling,
// restoreAllowCeiling and restoreSecrets — the same way
// servemcpstate_test.go covers checkSnapshotFits and restoreAllow: nothing
// here boots a machine, because the whole point is that a restore this
// clearly wrong never gets that far.
//
// policyFrom, which builds the *config.Config these free functions take, is
// sessions_test.go's — one helper for the package rather than a second copy.

// Firecracker takes vcpu and memory from the state file, so a restore cannot
// shrink a machine to fit a ceiling — mirrors
// TestRestoreHoldsAFrozenMachineToTheCeiling in servemcpstate_test.go, whose
// checkSnapshotFits this is the CLI's own copy of.
func TestCheckSnapshotCeiling(t *testing.T) {
	cfg := policyFrom(t, "[resources]\ncpus = 2\nmem = \"512M\"\n")

	if err := checkSnapshotCeiling(cfg, "ok", &sandbox.SnapshotMeta{VcpuCount: 2, MemMiB: 512}); err != nil {
		t.Errorf("a machine exactly at the ceiling was refused: %v", err)
	}
	big := &sandbox.SnapshotMeta{VcpuCount: 8, MemMiB: 512}
	err := checkSnapshotCeiling(cfg, "big", big)
	if err == nil {
		t.Fatal("an 8 vcpu machine was restored under a 2 vcpu ceiling")
	}
	for _, want := range []string{"8 vcpu", "cpus = 2", "kelyfos.toml:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if err := checkSnapshotCeiling(cfg, "fat", &sandbox.SnapshotMeta{VcpuCount: 1, MemMiB: 4096}); err == nil {
		t.Error("a 4 GiB machine was restored under a 512 MiB ceiling")
	}

	// An older snapshot does not say how large it is, and a ceiling cannot be
	// checked against nothing.
	err = checkSnapshotCeiling(cfg, "ancient", &sandbox.SnapshotMeta{})
	if err == nil {
		t.Fatal("a snapshot of unknown size was waved through a ceiling")
	}
	if !strings.Contains(err.Error(), "take the snapshot again") {
		t.Errorf("the refusal does not say how to fix it:\n%v", err)
	}

	// No -policy, no ceiling — today's behaviour, unchanged.
	if err := checkSnapshotCeiling(nil, "ancient", &sandbox.SnapshotMeta{}); err != nil {
		t.Errorf("with no policy there is no ceiling, but: %v", err)
	}
}

// A restore may narrow what a named policy permits and never widen it —
// mirrors the policy half of TestRestoreAllowHasTwoCeilings
// (servemcpstate_test.go); the snapshot's-own-list half of that test stays
// enforced the way it always was, by list's own default and by
// restoreNetwork, and restoreAllowCeiling is only the second ceiling.
func TestRestoreAllowCeilingNarrowsToPolicy(t *testing.T) {
	cfg := policyFrom(t, "[sandbox]\nallow = [\"api.github.com\", \"example.com\"]\n")

	if err := restoreAllowCeiling(cfg, []string{"example.com"}); err != nil {
		t.Errorf("a domain the policy permits was refused: %v", err)
	}

	err := restoreAllowCeiling(cfg, []string{"evil.example.net"})
	if err == nil {
		t.Fatal("a restore widened past the project's own allowlist")
	}
	for _, want := range []string{"evil.example.net", "kelyfos.toml", "api.github.com"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}

	// No -policy, nothing to narrow against — today's behaviour, unchanged.
	if err := restoreAllowCeiling(nil, []string{"anything.example"}); err != nil {
		t.Errorf("with no policy there is nothing to narrow against, but: %v", err)
	}
}

// restoreSecrets: an explicit --secret always wins and is checked against the
// restore's own allowlist exactly as it was before F9; with none typed, a
// named policy supplies its own, filtered to what this restore can actually
// reach rather than erroring on the rest — the same tolerance
// sandbox_restore's own policy-secrets loop gives it in
// host/servemcpstate.go's toolRestore.
func TestRestoreSecretsPrefersExplicitThenFallsBackToPolicy(t *testing.T) {
	// egress.ParseSecret reads the value from the host environment, so the
	// names this test uses have to actually be set (D6: a value never lives
	// in kelyfos.toml itself).
	t.Setenv("MY_TOKEN", "explicit-value")
	t.Setenv("GH_TOKEN", "policy-value")
	t.Setenv("UNREACHABLE", "policy-value")

	cfg := policyFrom(t, "[sandbox]\n"+
		"allow = [\"api.github.com\", \"example.com\"]\n"+
		"secrets = [\"GH_TOKEN@api.github.com\", \"UNREACHABLE@other.example.net\"]\n")

	// Explicit wins, and is still held to the restore's own allowlist.
	vetted, err := restoreSecrets(cfg, []string{"MY_TOKEN@example.com"}, []string{"example.com"})
	if err != nil {
		t.Fatalf("an explicit secret for an allowed domain was refused: %v", err)
	}
	if len(vetted) != 1 || vetted[0].Domain != "example.com" {
		t.Errorf("vetted = %v, want the one explicit secret", vetted)
	}
	if _, err := restoreSecrets(cfg, []string{"MY_TOKEN@not-allowed.example"}, []string{"example.com"}); err == nil {
		t.Fatal("an explicit secret for a domain outside the restore's allowlist was accepted")
	}

	// With none typed, the policy's own secrets fill in, silently dropping the
	// one whose domain this restore cannot reach rather than erroring on it —
	// a kelyfos.toml written for the whole project will usually name more
	// than any one snapshot's allowlist covers.
	vetted, err = restoreSecrets(cfg, nil, []string{"api.github.com"})
	if err != nil {
		t.Fatalf("policy secrets were refused: %v", err)
	}
	if len(vetted) != 1 || vetted[0].Domain != "api.github.com" {
		t.Errorf("vetted = %v, want just the policy secret whose domain this restore reaches", vetted)
	}

	// No policy, nothing typed: nothing to attach, no error — today's
	// behaviour, unchanged.
	vetted, err = restoreSecrets(nil, nil, []string{"api.github.com"})
	if err != nil || len(vetted) != 0 {
		t.Errorf("vetted = %v, err = %v; want nothing with no policy and nothing typed", vetted, err)
	}
}

// End to end through the CLI's own flag parsing: -policy is read, and a
// snapshot whose recorded size exceeds it is refused before snapshotRestore
// goes anywhere near sandbox.Restore, exactly as it is refused through
// serve-mcp's sandbox_restore. This is the one piece of F9 that a VM cannot
// add coverage for beyond what this already proves, because the whole point
// of the ceiling is that a restore this wrong never boots anything.
func TestSnapshotRestoreCLIEnforcesNamedPolicyCeiling(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeSnapshot(t, "big-machine", sandbox.SnapshotMeta{
		Arch: "x86_64", Flavor: "dev", VcpuCount: 8, MemMiB: 512,
	})
	dir := t.TempDir()
	policyPath := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(policyPath, []byte("[resources]\ncpus = 2\nmem = \"512M\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := snapshotRestore([]string{"-name", "big-machine", "-policy", policyPath})
	if err == nil {
		t.Fatal("an 8 vcpu snapshot restored on the command line under a -policy with a 2 vcpu ceiling")
	}
	for _, want := range []string{"8 vcpu", "cpus = 2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// Same shape, for the allowlist: a networked snapshot whose own list reaches
// somewhere a named policy does not permit is refused before restoreNetwork
// ever opens a TAP or binds a proxy for it.
func TestSnapshotRestoreCLIEnforcesNamedPolicyAllowlist(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	writeSnapshot(t, "networked", sandbox.SnapshotMeta{
		Arch: "x86_64", Flavor: "dev", VcpuCount: 1, MemMiB: 256,
		HasNetwork: true, Allow: []string{"evil.example.net"},
	})
	dir := t.TempDir()
	policyPath := filepath.Join(dir, config.FileName)
	if err := os.WriteFile(policyPath, []byte("[sandbox]\nallow = [\"example.com\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := snapshotRestore([]string{"-name", "networked", "-policy", policyPath})
	if err == nil {
		t.Fatal("a restore reached a domain the named policy does not permit")
	}
	if !strings.Contains(err.Error(), "evil.example.net") {
		t.Errorf("the refusal does not name the domain it refused:\n%v", err)
	}
}
