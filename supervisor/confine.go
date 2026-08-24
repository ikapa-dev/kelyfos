package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

// Applying a profile to a child and not to ourselves (P5-3).
//
// Landlock and seccomp both restrict the calling thread, and both are inherited
// across fork and exec. Confining a child therefore means running code in the
// child between fork and exec — and Go gives no safe hook there: after fork,
// only async-signal-safe work is legal, which rules out the Go runtime.
//
// So this binary re-execs itself. The supervisor rewrites the command to
//
//	/proc/self/exe --confine <flavor> --path <resolved> -- <argv...>
//
// and the process that starts applies the profile to itself and then execve()s
// the real program. Nothing of the Go runtime has to survive the restrictions:
// they go on immediately before the exec that replaces this process entirely.
//
// The original argv is carried through untouched, which is not fussiness —
// BusyBox is one binary that decides what to be from argv[0], so a wrapper that
// helpfully rewrote it would turn `sh` into something else.
//
// The cost is one extra execve per spawned process. That is a fraction of a
// millisecond and it does not sit on the boot path.

const confineFlag = "--confine"

// isConfineInvocation reports whether this process was started as the confining
// step rather than as PID 1. It is checked before anything else in main,
// because this process is not a supervisor and must not behave like one.
func isConfineInvocation(args []string) bool {
	return len(args) > 1 && args[1] == confineFlag
}

// runConfined applies a profile to this process and execs the real program. It
// never returns.
func runConfined(args []string) {
	flavor, path, argv, err := parseConfineArgs(args)
	if err != nil {
		confineFail(err)
	}
	profile := profileFor(flavor)

	// Every restriction below lands on the thread that applies it. execve
	// collapses this process to a single thread, and that thread is this one.
	runtime.LockOSThread()

	if err := applyLandlock(profile); err != nil {
		confineFail(fmt.Errorf("landlock: %w", err))
	}
	if err := applySeccomp(profile); err != nil {
		confineFail(fmt.Errorf("seccomp: %w", err))
	}

	if err := syscall.Exec(path, argv, os.Environ()); err != nil {
		// Reaching here means the profile refused the program itself, or the
		// binary went away between the supervisor resolving it and now.
		confineFail(fmt.Errorf("exec %s: %w", path, err))
	}
}

func parseConfineArgs(args []string) (flavor, path string, argv []string, err error) {
	// args is os.Args: [self, --confine, <flavor>, --path, <path>, --, argv...]
	if len(args) < 7 || args[1] != confineFlag || args[3] != "--path" || args[5] != "--" {
		return "", "", nil, fmt.Errorf("malformed confine invocation: %v", args)
	}
	return args[2], args[4], args[6:], nil
}

// confineFail reports on stderr — which is the caller's own pipe, so the
// message reaches whoever ran the command — and exits 126, the conventional
// status for "found it, could not run it".
func confineFail(err error) {
	fmt.Fprintf(os.Stderr, "kelyfos: refusing to run unconfined: %v\n", err)
	os.Exit(126)
}

// guestProfile is this machine's profile, resolved once at boot from the kernel
// command line. A nil value means the supervisor has not decided yet, which
// only happens before setup runs.
var guestProfile *Profile

// confine rewrites a command so the process it starts is confined.
//
// It is called from reaper.startAndRegister rather than from each of exec, the
// plugin host and the shell, for the reason requireJail lives in sandbox.New:
// a confinement three call sites have to remember is a confinement one of them
// will eventually forget, and it will be the one somebody uses.
func confine(cmd *exec.Cmd) {
	if guestProfile == nil || cmd.Err != nil || cmd.Path == "" {
		// cmd.Err is already set when the command was not found; leaving it
		// alone keeps `kelyfos exec nosuchthing` reporting not-found rather
		// than a confinement failure.
		return
	}
	if strings.HasSuffix(cmd.Path, confineHelperMarker) {
		return // already wrapped; nothing wraps twice
	}
	real, argv := cmd.Path, append([]string{}, cmd.Args...)
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{confineHelperMarker,
		confineFlag, guestProfile.Name, "--path", real, "--"}, argv...)
}

// confineHelperMarker is the argv[0] the confining step runs under, so that a
// `ps` inside the guest during the microsecond it exists says what it is.
const confineHelperMarker = "kelyfos-confine"

// profileSummary and profileError are what the ready frame carries: what is
// enforced, or why nothing is. Exactly one of them is ever non-empty.
var (
	profileSummary string
	profileError   string
)

// setupProfile resolves this machine's profile and proves the kernel can apply
// it, once, at boot.
//
// The proof is a real landlock_create_ruleset asking for the ABI version, which
// is the only question about Landlock a process can ask without side effects. A
// kernel that answers is a kernel that has it; a kernel with the LSM compiled
// in but left out of CONFIG_LSM answers ENOSYS just like one built without it,
// which is exactly why this is asked of the kernel rather than read off a
// config file (docs/hardening.md §4.1).
//
// A failure here does not clear guestProfile. The confining step still runs and
// still refuses, so a machine the host somehow started anyway spawns nothing
// rather than spawning it unconfined.
func setupProfile() {
	flavor := kernelParam("kelyfos.flavor")
	p := profileFor(flavor)
	guestProfile = &p

	abi, err := landlockABI()
	switch {
	case err != nil:
		profileError = fmt.Sprintf("landlock is not available in this kernel (%v); "+
			"the image needs CONFIG_SECURITY_LANDLOCK=y and landlock named in CONFIG_LSM", err)
	case abi < minLandlockABI:
		profileError = fmt.Sprintf("landlock ABI %d is older than the %d this profile needs",
			abi, minLandlockABI)
	default:
		profileSummary = fmt.Sprintf("landlock abi %d · %s", abi, p.Describe())
	}
	if profileError != "" {
		logf("profile: %s", profileError)
		return
	}
	logf("profile: %s", profileSummary)
}
