package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The VMM watchdog (ST-5.3, the prevention half of IA-M1): a tiny re-exec of
// this binary whose only job is to outlive its parent by one action — when
// the kelyfos process that booted a machine dies without its teardown, the
// watchdog stops the machine and frees its network names.
//
// The mechanism has to be a separate process, and it is worth writing down
// why nothing smaller works. A goroutine cannot act after its process dies. A
// watchdog waiting on a pipe would need a writer that outlives the process —
// which is the same problem one layer up. The kernel's own mechanism,
// prctl(PR_SET_PDEATHSIG), delivers a signal when the parent dies, and Go
// sets it through SysProcAttr.Pdeathsig on the child at spawn — so the
// watchdog is spawned with Pdeathsig SIGTERM and a handler that does the
// cleanup: the one place in the chain where "my parent just died" is
// executable code.
//
// The chain it covers: kelyfos → sudo → jailer(exec) → firecracker. Pdeathsig
// is set on the direct child (sudo, or firecracker unjailed), which takes the
// direct child down with the parent. Through the jailer the VMM survives its
// wrapper's death — the wrapper exec'd away — and that is what the watchdog
// is for: it holds the VMM's pid file location, learns of the death, SIGKILLs
// the VMM and frees the TAP and table. A watchdog that was SIGKILLed itself
// cannot act; that residue is what the doctor reaper sweeps (ST-0.2).
//
// Lifecycle: the watchdog exits on its own the moment the VMM is gone (a
// normal teardown removes it before the parent dies, so the cleanup path is
// then a no-op), and the sandbox kills it explicitly during teardown.
const vmmWatchdogEnv = "KELYFOS_VMM_WATCHDOG"

// spawnVMMWatchdog starts the watchdog for this sandbox's machine, if the
// binary can be located. Best-effort by design: a watchdog that could not
// start leaves the post-death cleanup to the doctor reaper, which exists for
// exactly that, and a sandbox that refused to boot because its watchdog
// failed would be defending the machine against its own operator.
func (s *Sandbox) spawnVMMWatchdog() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), vmmWatchdogEnv+"="+s.State.RunDir)
	cmd.SysProcAttr = watchdogSpawnAttr()
	if err := cmd.Start(); err != nil {
		return
	}
	s.watchdog = cmd.Process
}

// stopVMMWatchdog ends the watchdog on the clean path, so a normal teardown
// never leaves it polling a dead machine.
func (s *Sandbox) stopVMMWatchdog() {
	if s.watchdog != nil {
		_ = s.watchdog.Kill()
		s.watchdog = nil
	}
}

// runVMMWatchdog is the watchdog's whole life, run from main when the env
// marker is set. It exits on its own the moment the VMM is gone — a normal
// teardown gets there first, making every cleanup here a no-op — and acts
// only when the parent is gone while the VMM is still running.
func RunVMMWatchdog(runDir string) {
	// runDir is the jail's root directory: <cache>/run/firecracker/<id>/root.
	jailDir := filepath.Dir(runDir)
	id := filepath.Base(jailDir)
	pidPath := filepath.Join(runDir, "firecracker.pid")
	parent := os.Getppid()

	// Go's known Pdeathsig race: if the parent died between fork and prctl,
	// Getppid re-parented us to init before we ever ran — cleanup now, rather
	// than polling a parent that will never die again (review, finding 7b).
	if os.Getppid() == 1 {
		cleanupOrphanedMachine(id, pidPath, jailDir)
		os.Exit(0)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGTERM)

	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-sig:
			cleanupOrphanedMachine(id, pidPath, jailDir)
			os.Exit(0)
		case <-tick.C:
		}
		if !processExists(parent) {
			cleanupOrphanedMachine(id, pidPath, jailDir)
			os.Exit(0)
		}
		if vmm := readVMMpid(pidPath); vmm > 0 && !processAlive(vmm) {
			// The VMM is gone and the parent lives: the teardown is running
			// its normal course, and there is nothing to clean.
			os.Exit(0)
		}
	}
}

// cleanupOrphanedMachine stops the VMM, frees its TAP and nft table, and
// removes the jail directory — every action best-effort, because whatever
// survives is the doctor reaper's already.
func cleanupOrphanedMachine(id, pidPath, jailDir string) {
	if vmm := readVMMpid(pidPath); vmm > 0 && processAlive(vmm) {
		// syscall.Kill, not exec'd kill: no PATH dependency, and the error
		// comes back to be logged rather than discarded (review, finding 7c).
		if err := unix.Kill(vmm, unix.SIGKILL); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos watchdog: kill %d: %v\n", vmm, err)
		}
	}
	if msg := RemoveNetworkResidue(id); msg != "" {
		_ = msg
	}
	if err := os.RemoveAll(jailDir); err != nil {
		// The jailer leaves root-owned files; a plain RemoveAll fails on every
		// jailed machine. The same sudo fallback removeJail makes (review,
		// finding 5) — and anything still left is visible to the doctor scan,
		// which now reports run dirs with no live claim.
		if err := exec.Command("sudo", "-n", "rm", "-rf", jailDir).Run(); err != nil {
			fmt.Fprintf(os.Stderr, "kelyfos watchdog: jail dir %s: %v\n", jailDir, err)
		}
	}
}

func readVMMpid(pidPath string) int {
	blob, err := os.ReadFile(pidPath)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(blob)))
	if err != nil || pid <= 0 {
		return 0
	}
	return pid
}

func processExists(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil
}

// processAlive is processExists with the zombie rejected: a zombie supervises
// nothing and a kill aimed at one is a no-op that hides a mistake.
func processAlive(pid int) bool {
	blob, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	stat := string(blob)
	state := stat[strings.LastIndexByte(stat, ')')+2:]
	return !strings.HasPrefix(state, "Z")
}
