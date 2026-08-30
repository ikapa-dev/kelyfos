package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/config"
)

// The shim and `kelyfos run` are two entry paths onto one wall, and the thing
// that would quietly rot is the second one drifting off the first: a cap added
// to [resources] and wired into run.go, and nobody remembering the shim.
//
// This does not test the shim's plumbing — that needs a machine. It tests the
// part that goes stale silently: that every enforceable cap the parser accepts
// is one the shim actually carries. A new key fails here until it is.
func TestShimCarriesEveryEnforceableCap(t *testing.T) {
	// The caps a sandbox is built with, as opposed to the ones the host holds
	// for itself. A time budget is a host timer over a run with an end, which
	// is not what the shim's sandboxes are — they live until the SDK kills
	// them — so those two are named here as deliberately out rather than
	// forgotten.
	hostSide := map[string]string{
		"max_runtime":  "a host timer over a run with an end; a shim sandbox lives until its client kills it",
		"idle_timeout": "the same, and its activity signal is the run's recorder and proxy",
		"disk":         "a ceiling on a packed workspace, and the shim attaches none",
	}
	carried := map[string]bool{
		"cpus": true, "mem": true, "cpu_quota": true, "scratch": true,
		"net_mbps_rx": true, "net_mbps_tx": true, "disk_iops": true, "disk_mbps": true,
	}

	for _, k := range config.KeysIn("resources") {
		if !k.Accepted() {
			continue
		}
		if why, deliberate := hostSide[k.Name]; deliberate {
			if carried[k.Name] {
				t.Errorf("%s is listed both as carried and as deliberately host-side (%s)", k.Name, why)
			}
			continue
		}
		if !carried[k.Name] {
			t.Errorf("[resources] %s is enforceable and the shim does not carry it.\n"+
				"Wire it into shim.Policy and shimCmd, or say here why it is host-side only — "+
				"a cap that applies to `kelyfos run` and not to the shim is a hole in the wall "+
				"(F-D33).", k.Name)
		}
	}
}

// A policy file the shim can read is the whole premise, so check the resolution
// the CLI depends on rather than trusting that Find walks upward.
func TestShimFindsThePolicyFromASubdirectory(t *testing.T) {
	root := t.TempDir()
	body := "[sandbox]\nimage = \"dev\"\n\n[resources]\ncpus = 1\nmem = \"384M\"\n"
	if err := os.WriteFile(filepath.Join(root, config.FileName), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}

	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(deep); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("no policy found from a subdirectory; the shim would run uncapped")
	}
	if cfg.ResCPUs != 1 || cfg.ResMemMiB != 384 {
		t.Errorf("policy read wrong: cpus=%d mem=%d MiB", cfg.ResCPUs, cfg.ResMemMiB)
	}
}
