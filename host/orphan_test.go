package main

import (
	"strings"
	"testing"
)

// The orphan scan's decision core, tested against synthetic process tables
// rather than a live machine — the same split sessionsSizeCheck makes in
// doctor.go. The live behaviour (a real SIGKILLed run listed exactly, reaped
// exactly, clean afterwards) is the acceptance test's, and was executed on the
// dev VM before this landed.

func orphanTestProc(pid, ppid int, comm, state, cmdline string) procInfo {
	return procInfo{PID: pid, PPID: ppid, Comm: comm, State: state[0], Cmdline: cmdline, StartMS: 0}
}

// The jailer wrapper is the identity anchor for a jailed VMM: the jailer
// execs into Firecracker, whose argv becomes chroot-relative and whose
// /proc/<pid>/root resolves to `/` from outside the jail — so the id and the
// cache only survive on the wrapper's argv.
func TestJailerWrapFrom_ArgvCarriesTheIdAndTheCache(t *testing.T) {
	sudo := orphanTestProc(100, 50, "sudo", "S",
		"sudo -n jailer --id fe759662 --exec-file /usr/local/bin/firecracker --uid 501 --gid 1000 "+
			"--chroot-base-dir /home/u/.cache/kelyfos-cache.71jovJ/run -- --api-sock /fc.sock --config-file /config.json")
	w, ok := jailerWrapFrom(sudo)
	if !ok {
		t.Fatal("a jailer wrapper was not identified")
	}
	if w.id != "fe759662" {
		t.Fatalf("wrapper id %q, want fe759662", w.id)
	}
	// The cache is the run root the jailer was handed minus the /run.
	if w.cache != "/home/u/.cache/kelyfos-cache.71jovJ" {
		t.Fatalf("wrapper cache %q", w.cache)
	}
	if _, ok := jailerWrapFrom(orphanTestProc(101, 1, "firecracker", "S", "/firecracker")); ok {
		t.Fatal("a VMM is not a wrapper")
	}
}

func TestVMMIdentity_ComesFromTheWrapperWhenThereIsOne(t *testing.T) {
	w := jailerWrap{id: "fe759662", cache: "/home/u/.cache/kelyfos-cache.71jovJ"}
	fc := orphanTestProc(101, 100, "firecracker", "S",
		"/firecracker --id fe759662 --api-sock /fc.sock --config-file /config.json")
	id, cache, ok := vmmIdentity(fc, "/", &w)
	if !ok || id != "fe759662" || cache != w.cache {
		t.Fatalf("jailed VMM identity ok=%v id=%q cache=%q", ok, id, cache)
	}
}

// A bare firecracker somebody is running by hand — no wrapper, a chroot-less
// root link, a socket path that is not under a run directory — is nobody's
// proof, and the scan's contract is to leave it entirely alone.
func TestVMMIdentity_RefusesAForeignFirecracker(t *testing.T) {
	foreign := orphanTestProc(200, 1, "firecracker", "S",
		"firecracker --api-sock /tmp/someone-elses.sock --config-file /tmp/cfg.json")
	if _, _, ok := vmmIdentity(foreign, "/", nil); ok {
		t.Fatal("a firecracker with no KelyfOS evidence was claimed as ours")
	}
	other := orphanTestProc(201, 1, "python3", "S", "python3 -m http.server")
	if _, _, ok := vmmIdentity(other, "/", nil); ok {
		t.Fatal("a process that is not a VMM at all was claimed as ours")
	}
}

// An unjailed VMM has no wrapper and no jail chroot: its identity is the
// api-sock path under its run directory, which is the only thing its argv
// carries.
func TestVMMIdentity_AnUnjailedVMMIsKnownByItsSocketPath(t *testing.T) {
	fc := orphanTestProc(300, 1, "firecracker", "S",
		"firecracker --api-sock /home/u/.cache/kelyfos/run/firecracker/abcd1234/firecracker.sock")
	id, cache, ok := vmmIdentity(fc, "/", nil)
	if !ok || id != "abcd1234" || cache != "/home/u/.cache/kelyfos" {
		t.Fatalf("unjailed identity ok=%v id=%q cache=%q", ok, id, cache)
	}
}

// A peer worktree's boot in progress has a live kelyfos process in the VMM's
// ancestor chain. That chain is the whole difference between "orphaned" and
// "somebody else's machine" — reading one ppid would false-positive on it.
func TestOrphanedVMM_ALiveKelyfosAnywhereInTheChainClaims(t *testing.T) {
	procs := map[int]procInfo{
		1:  orphanTestProc(1, 0, "systemd", "S", ""),
		10: orphanTestProc(10, 1, "kelyfos", "S", "kelyfos run"),         // the peer's run, live
		11: orphanTestProc(11, 10, "sudo", "S", "sudo -n jailer --id x"), // live wrapper
		12: orphanTestProc(12, 11, "firecracker", "S", "/firecracker"),
	}
	if orphanedVMM(procs[12], procs) {
		t.Fatal("a VMM whose chain holds a live kelyfos was called orphaned")
	}
}

func TestOrphanedVMM_AKilledRunOrphansItsVMM(t *testing.T) {
	// kill -9 the run: the wrapper reparents to init and stays alive waiting
	// on the VMM, and the VMM's chain now reaches no live kelyfos.
	procs := map[int]procInfo{
		1:  orphanTestProc(1, 0, "systemd", "S", ""),
		11: orphanTestProc(11, 1, "sudo", "S", "sudo -n jailer --id deadbeef"),
		12: orphanTestProc(12, 11, "firecracker", "S", "/firecracker"),
	}
	if !orphanedVMM(procs[12], procs) {
		t.Fatal("a VMM whose supervisor chain is dead was not called orphaned")
	}
}

// A zombie supervises nothing: a chain through one continues upwards, and a
// zombie kelyfos does not claim the machine it left behind.
func TestOrphanedVMM_AZombieDoesNotClaimItsChild(t *testing.T) {
	procs := map[int]procInfo{
		1:  orphanTestProc(1, 0, "systemd", "S", ""),
		10: orphanTestProc(10, 1, "kelyfos", "Z", "kelyfos run"), // killed, not yet reaped
		11: orphanTestProc(11, 10, "firecracker", "S", "/firecracker"),
	}
	if !orphanedVMM(procs[11], procs) {
		t.Fatal("a VMM under a zombie kelyfos was treated as supervised")
	}
}

func TestGroupOrphans_DeduplicatesOnFindingIdentity(t *testing.T) {
	vmm := orphan{Kind: orphanKindVMM, ID: "ab12cd34", PID: 7}
	got := groupOrphans([]orphan{vmm, vmm, {Kind: orphanKindTAP, ID: "ab12cd34"}})
	if n := len(got["ab12cd34"]); n != 2 {
		t.Fatalf("grouping kept %d findings for one id, want the deduped VMM and the TAP", n)
	}
}

// The check is advisory by design — the machine can run KelyfOS with orphans
// on it — so its ok/warn split must never count toward doctor's exit code.
func TestOrphansCheck_WarnsAndListsWithoutFailing(t *testing.T) {
	found := []orphan{
		{Kind: orphanKindVMM, ID: "ab12cd34", PID: 7, Detail: "pid 7 firecracker, up 90 s"},
		{Kind: orphanKindTAP, ID: "ef56ab12", Detail: "TAP kelyfosef56ab12 unclaimed"},
	}
	c := orphansCheck(found, false)
	if c.ok {
		t.Fatal("a scan with residue reported ok")
	}
	if !c.warn {
		t.Fatal("the orphan check must be advisory (warn), not a failure")
	}
	for _, want := range []string{"1 orphaned VMM(s)", "1 leftover TAP(s)", "0 leftover nft table(s)", "pid 7 firecracker", "kelyfos doctor --reap-orphaned"} {
		if !strings.Contains(c.detail+c.fix, want) {
			t.Fatalf("report is missing %q\n detail: %s\n fix: %s", want, c.detail, c.fix)
		}
	}
}

func TestOrphansCheck_CleanReportsNone(t *testing.T) {
	c := orphansCheck(nil, false)
	if !c.ok || c.warn {
		t.Fatalf("a clean scan must be ok without warning: %+v", c)
	}
	if !strings.Contains(c.detail, "none") {
		t.Fatalf("clean detail %q should say none", c.detail)
	}
	if reaped := orphansCheck(nil, true); !strings.Contains(reaped.detail, "removed") {
		t.Fatalf("post-reap detail %q should credit the reaper", reaped.detail)
	}
}
