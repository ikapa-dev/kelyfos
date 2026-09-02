package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ikapa-dev/kelyfos/internal/denial"
	"github.com/ikapa-dev/kelyfos/internal/sandbox"
)

// withHostSeams pins the host's own ceilings to known numbers for the length of
// one test. hostCPUCeiling and hostMemCeilingMiB are package-level vars for
// exactly this: the M1 clamp/refuse split and the M2b host-snapshot ceiling
// turn on the precise figure, and a test cannot assert against whatever the
// machine running it happens to have. Restored on cleanup, and tests in this
// package run sequentially, so the override is invisible to every other test.
func withHostSeams(t *testing.T, cpus, memMiB int) {
	t.Helper()
	origCPU, origMem := hostCPUCeiling, hostMemCeilingMiB
	hostCPUCeiling = func() int { return cpus }
	hostMemCeilingMiB = func() int { return memMiB }
	t.Cleanup(func() {
		hostCPUCeiling = origCPU
		hostMemCeilingMiB = origMem
	})
}

// The audit of 2026-09-01's A8: a policy-less serve-mcp let a client name its
// own cpus and mem, and the request went to Firecracker verbatim — a
// one-call host DoS. The machine's own ceilings now apply on every path,
// policy or not, and the audit's exact ask (mem=262144) is refused with a
// structured error.

func TestARequestAboveTheHostsOwnMemoryIsRefused(t *testing.T) {
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	// Twice whatever this machine can carry: refused whatever the machine is.
	ask := hostMemCeilingMiB()*2 + 512
	_, err := s.resolve(&runArgs{Mem: fmt.Sprintf("%dM", ask)})
	if err == nil {
		t.Fatalf("a %d MiB machine was accepted on a host with a %d MiB ceiling", ask, hostMemCeilingMiB())
	}
	for _, want := range []string{"[ceiling.host]", "what this host can run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

func TestARequestAboveTheHostsOwnCPUIsRefused(t *testing.T) {
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	ask := hostCPUCeiling()*4 + 4
	_, err := s.resolve(&runArgs{CPUs: ask})
	if err == nil {
		t.Fatalf("%d vcpu was accepted on a %d-core host", ask, hostCPUCeiling())
	}
	if !strings.Contains(err.Error(), "[ceiling.host]") {
		t.Errorf("the refusal is not the catalog one:\n%v", err)
	}
}

// The audit's exact repro, verbatim from the report: the policy-less door
// asked for 262144 MiB.
func TestTheAuditReproIsRefused(t *testing.T) {
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	res := s.toolRun(json.RawMessage(`{"image":"dev","cpus":4096,"mem":"262144"}`))
	if !res.IsError {
		t.Fatal("the audit's oversized run was accepted")
	}
	text := res.Content[0].Text
	if !strings.Contains(text, "ceiling") {
		t.Errorf("the refusal does not name a ceiling:\n%s", text)
	}
}

// A normal ask still passes, policy-less: the ceiling must not make the
// default door unusable.
func TestAReasonableAskPassesWithoutAPolicy(t *testing.T) {
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	opts, err := s.resolve(&runArgs{CPUs: 1, Mem: "512M"})
	if err != nil {
		t.Fatalf("the default-sized machine was refused: %v", err)
	}
	if opts.VcpuCount != 1 || opts.MemMiB != 512 {
		t.Errorf("got %d vcpu / %d MiB, want 1 / 512", opts.VcpuCount, opts.MemMiB)
	}
}

// The legacy [sandbox] mem_mib is a default on the CLI door; on this door a
// declared size is a ceiling, because the tool schema promises at most what
// the policy allows and a client naming its own size over it contradicts that
// whichever key spells it.
func TestALegacyMemMibIsACeilingOnThisDoor(t *testing.T) {
	s := serverWith(t, `[sandbox]
image = "dev"
allow = ["example.com"]
mem_mib = 512
`)
	_, err := s.resolve(&runArgs{Mem: "1024M"})
	if err == nil {
		t.Fatal("a client raised mem over the legacy mem_mib ceiling")
	}
	for _, want := range []string{"mem_mib = 512", "ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	// Asking for less is what the door is for.
	if _, err := s.resolve(&runArgs{Mem: "256M"}); err != nil {
		t.Errorf("asking under the legacy ceiling was refused: %v", err)
	}
}

// The policy-path host ceilings were the half the first test pass missed:
// every A8 test drove the policy-less door, so removing capToHost from the
// policy path passed the suite silently (adversarial review, A8). This one
// resolves through a policy — the ceilings must hold there too.
func TestA8_TheHostCeilingsHoldOnThePolicyPath(t *testing.T) {
	// A policy with no [resources] ceilings of its own: the host's are what
	// must fire. (With a [resources] mem below the host ceiling, the policy
	// refusal fires first — that order is correct and tested elsewhere.)
	s := serverWith(t, `[sandbox]
image = "dev"
allow = ["example.com"]
`)
	ask := hostMemCeilingMiB()*2 + 512
	if _, err := s.resolve(&runArgs{CPUs: 1, Mem: fmt.Sprintf("%dM", ask)}); err == nil {
		t.Fatalf("a %d MiB machine passed the policy path's host ceiling", ask)
	} else if !strings.Contains(err.Error(), "[ceiling.host]") {
		t.Errorf("the refusal is not the catalog one:\n%v", err)
	}
	askCPUs := hostCPUCeiling()*4 + 4
	if _, err := s.resolve(&runArgs{CPUs: askCPUs}); err == nil {
		t.Fatalf("%d vcpu passed the policy path's host ceiling", askCPUs)
	}
}

// The legacy vcpus key is a ceiling on this door, the same as mem_mib — the
// mem half was tested at first and this half was not, which is exactly how a
// claim like "both keys are ceilings" gets half-implemented.
func TestA8_TheLegacyVcpusIsACeilingOnThisDoor(t *testing.T) {
	s := serverWith(t, `[sandbox]
image = "dev"
allow = ["example.com"]
vcpus = 2
`)
	_, err := s.resolve(&runArgs{CPUs: 4})
	if err == nil {
		t.Fatal("a client raised cpus over the legacy vcpus ceiling")
	}
	for _, want := range []string{"vcpus = 2", "ceiling"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
	if _, err := s.resolve(&runArgs{CPUs: 1}); err != nil {
		t.Errorf("asking under the legacy ceiling was refused: %v", err)
	}
}

// --- M1: a default is clamped to the host; only an explicit ask is refused ----

// The committed capToHost REFUSED its own 2-vcpu default, so serve-mcp would
// not boot at all on a one-core or cpuset-pinned host. A size the client did
// not ask for is now clamped to what the host can run, not refused (audit
// 2026-09-01, M1). This test fails on the pre-M1 HEAD for exactly that reason.
func TestM1_ADefaultIsClampedToTheHostNotRefused(t *testing.T) {
	withHostSeams(t, 1, 8192) // a one-core host
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	// No policy and no explicit cpus/mem: the default is 2 vcpu / 512 MiB.
	opts, err := s.resolve(&runArgs{})
	if err != nil {
		t.Fatalf("the 2-vcpu default was refused on a one-core host: %v", err)
	}
	if opts.VcpuCount != 1 {
		t.Errorf("the default was not clamped to the host: got %d vcpu, want 1", opts.VcpuCount)
	}
	// The memory default (512) is under the host's here, so it is untouched.
	if opts.MemMiB != 512 {
		t.Errorf("the memory default was altered: got %d MiB, want 512", opts.MemMiB)
	}
}

// The clamp is for defaults only: a client that names a size over the host is
// asking for a machine the host cannot give, and that is still refused.
func TestM1_AnExplicitAskAboveTheHostIsStillRefused(t *testing.T) {
	withHostSeams(t, 2, 2048)
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	if _, err := s.resolve(&runArgs{CPUs: 4}); !denial.Is(err, "ceiling.host") {
		t.Errorf("an explicit 4-cpu ask on a 2-core host was not refused by the host ceiling: %v", err)
	}
	if _, err := s.resolve(&runArgs{Mem: "4096M"}); !denial.Is(err, "ceiling.host") {
		t.Errorf("an explicit 4096 MiB ask on a 2048 MiB host was not refused: %v", err)
	}
}

// A size the client names that fits the host passes through as asked — neither
// clamped nor refused.
func TestM1_AnExplicitAskUnderTheHostPassesAsAsked(t *testing.T) {
	withHostSeams(t, 8, 8192)
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	opts, err := s.resolve(&runArgs{CPUs: 4, Mem: "2048M"})
	if err != nil {
		t.Fatalf("an explicit ask under the host was refused: %v", err)
	}
	if opts.VcpuCount != 4 || opts.MemMiB != 2048 {
		t.Errorf("got %d vcpu / %d MiB, want 4 / 2048 exactly as asked", opts.VcpuCount, opts.MemMiB)
	}
}

// --- M2: the legacy refusals are catalog denials; the host bounds a snapshot --

// M2a: the vcpus and mem_mib refusals are branchable catalog denials now, not
// bare fmt.Errorf.
func TestM2_TheLegacyCeilingRefusalsAreFromTheCatalog(t *testing.T) {
	sv := serverWith(t, `[sandbox]
image = "dev"
allow = ["example.com"]
vcpus = 2
`)
	if _, err := sv.resolve(&runArgs{CPUs: 4}); !denial.Is(err, "ceiling.tool_legacy") {
		t.Errorf("the vcpus refusal is not the catalog ceiling.tool_legacy: %v", err)
	}
	sm := serverWith(t, `[sandbox]
image = "dev"
allow = ["example.com"]
mem_mib = 512
`)
	if _, err := sm.resolve(&runArgs{Mem: "1024M"}); !denial.Is(err, "ceiling.tool_legacy") {
		t.Errorf("the mem_mib refusal is not the catalog ceiling.tool_legacy: %v", err)
	}
}

// M2b: the host's own ceiling bounds a frozen machine too, even with no policy,
// and the refusal names the snapshot and what it holds.
func TestM2_ASnapshotBiggerThanTheHostIsRefusedByName(t *testing.T) {
	withHostSeams(t, 2, 2048)
	none := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}

	err := none.checkSnapshotFits("huge", &sandbox.SnapshotMeta{VcpuCount: 8, MemMiB: 512})
	if !denial.Is(err, "ceiling.host_snapshot") {
		t.Fatalf("an 8-vcpu snapshot on a 2-core host with no policy was not refused by the host: %v", err)
	}
	for _, want := range []string{"huge", "8 vcpu"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}
	if err := none.checkSnapshotFits("fat", &sandbox.SnapshotMeta{VcpuCount: 1, MemMiB: 8192}); !denial.Is(err, "ceiling.host_snapshot") {
		t.Errorf("an 8 GiB snapshot on a 2 GiB host was not refused: %v", err)
	}
	// An unsized snapshot with no policy is allowed: the host cannot decide it.
	if err := none.checkSnapshotFits("ancient", &sandbox.SnapshotMeta{}); err != nil {
		t.Errorf("an unsized snapshot with no policy was refused: %v", err)
	}
	// A snapshot exactly at the host ceiling fits.
	if err := none.checkSnapshotFits("ok", &sandbox.SnapshotMeta{VcpuCount: 2, MemMiB: 2048}); err != nil {
		t.Errorf("a snapshot exactly at the host ceiling was refused: %v", err)
	}
}

// The host ceiling reaches the two doors that restore a frozen machine, before
// either builds anything.
func TestM2_RestoreAndForkRefuseAnOversizedSnapshot(t *testing.T) {
	t.Setenv("KELYFOS_CACHE", t.TempDir())
	withHostSeams(t, 2, 2048)
	// No policy at all, so only the host ceiling can refuse it.
	s := &hostServer{arch: "x86_64", max: defaultMaxSandboxes, boxes: map[string]*servedBox{}}
	writeSnapshot(t, "toobig", sandbox.SnapshotMeta{Arch: "x86_64", Flavor: "dev", VcpuCount: 8, MemMiB: 512})

	res := s.toolRestore(json.RawMessage(`{"name":"toobig"}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "[ceiling.host_snapshot]") {
		t.Errorf("restore did not refuse an oversized snapshot with the host ceiling:\n%s", res.Content[0].Text)
	}
	res = s.toolFork(json.RawMessage(`{"name":"toobig","count":2}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "[ceiling.host_snapshot]") {
		t.Errorf("fork did not refuse an oversized snapshot with the host ceiling:\n%s", res.Content[0].Text)
	}
}
