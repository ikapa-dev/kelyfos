package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

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
