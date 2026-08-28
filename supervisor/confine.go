package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
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
//
// The rewrite is unconditional for every command that has a path to rewrite.
// The guard that used to stand here asked whether cmd.Path ended in
// confineHelperMarker — a property of the *target*, which is the agent's own
// argv[0] resolved. It therefore never fired for the case it was written for,
// because a command this function has already wrapped has Path "/proc/self/exe"
// and that never ends in the marker; and it fired for exactly one case it was
// not written for, a program the agent had named after the helper. Two commands
// from inside an ordinary confined exec were the whole of it:
//
//	printf '#!/bin/sh\nmount -o remount,rw /\n' > /root/kelyfos-confine
//	chmod +x /root/kelyfos-confine && exec /root/kelyfos-confine
//
// A script rather than the `cp /bin/sh …` the review wrote: /bin/sh here is a
// symlink to BusyBox, which decides what to be from argv[0] and refuses to be
// anything under that name. The finding is unaffected — what the old guard read
// was the path, not the program. The process that came out ran as PID 1's child
// with no Landlock domain and no seccomp filter (F8, security review of
// 2026-08-28).
//
// What replaces the guard is keyed on the wrapper's own identity, which is not a
// pair the agent can produce. Args[0] is the string the caller passed and Path
// is what exec.Command made of it, and the two do diverge — a bare name is
// resolved against PATH — but never into (confineHelperPath, marker):
//
//	a name with a separator is taken verbatim, so Path == "/proc/self/exe"
//	means Args[0] == "/proc/self/exe", which is not the marker;
//
//	a bare name goes through LookPath, which joins a PATH directory to that
//	same name, so a Path of "/proc/self/exe" would need the name "exe" — and
//	then Args[0] is "exe", which is not the marker either.
//
// And startAndRegister asserts the outcome rather than trusting this function to
// have no reachable early return.
func confine(cmd *exec.Cmd) {
	if guestProfile == nil || cmd.Err != nil || cmd.Path == "" {
		// cmd.Err is already set when the command was not found; leaving it
		// alone keeps `kelyfos exec nosuchthing` reporting not-found rather
		// than a confinement failure.
		return
	}
	if isConfineWrapper(cmd) {
		return // this is the wrapper itself; nothing wraps twice
	}
	real, argv := cmd.Path, append([]string{}, cmd.Args...)
	cmd.Path = confineHelperPath
	cmd.Args = append([]string{confineHelperMarker,
		confineFlag, guestProfile.Name, "--path", real, "--"}, argv...)
}

// isConfineWrapper reports whether cmd is already the confining step: both the
// path this process re-execs itself through and the argv[0] it does it under.
// Both halves, because either alone is something a caller could arrive at by
// accident — /proc/self/exe is a path anything may name, and argv[0] is a string
// anything may pass.
func isConfineWrapper(cmd *exec.Cmd) bool {
	return cmd.Path == confineHelperPath && len(cmd.Args) > 0 && cmd.Args[0] == confineHelperMarker
}

// confineHelperPath is how this binary re-execs itself. /proc/self/exe rather
// than os.Executable() because the supervisor is the only thing behind it and a
// path resolved once at boot is a path that can be replaced underneath.
const confineHelperPath = "/proc/self/exe"

// confineHelperMarker is the argv[0] the confining step runs under, so that a
// `ps` inside the guest during the microsecond it exists says what it is.
const confineHelperMarker = "kelyfos-confine"

// errNotConfined is what startAndRegister returns instead of spawning a process
// the profile was not applied to.
var errNotConfined = errors.New("refusing to start a process the guest profile was not applied to")

// confinementHolds is the invariant reaper.startAndRegister asserts after
// calling confine, and the half of F8's fix that makes the guarantee structural
// rather than exemplary.
//
// docs/threat-model.md promises that every process the supervisor spawns is
// confined. Before this, that promise rested on confine having no reachable
// path through it that returns without rewriting — a property a reader has to
// re-derive from scratch on every edit, and one that had in fact been false
// since the function was written. Now it rests on this instead: whatever confine
// does or fails to do, a command that is not the wrapper is not started. The
// supervisor already refuses to report ready on a profile it could not enforce;
// this is the same refusal one step earlier, where it stops a process rather
// than a status line.
func confinementHolds(cmd *exec.Cmd) error {
	if guestProfile == nil {
		// Deliberately not a refusal, and unreachable in this binary anyway.
		// Three facts hold it up, and the next person to touch this line is
		// relying on all three:
		//
		//  1. setupProfile assigns guestProfile unconditionally — even a
		//     kernel with no Landlock gets a Profile and a profileError, not a
		//     nil — so after boot this is never nil.
		//  2. It runs at main.go's isPID1 block, before any channel is served,
		//     so nothing can be spawned before it has run.
		//  3. A supervisor that is not PID 1 skips it, but never gets here:
		//     the --confine re-exec is intercepted at the top of main before
		//     anything else, and a second supervisor cannot bind the vsock
		//     ports PID 1 already holds, so it serves no exec, no shell and no
		//     plugin.
		//
		// It returns nil rather than refusing because that is D32: a pre-v0.9
		// image and a pre-v0.9 snapshot confine nothing and are warned about
		// rather than refused (docs/upgrading.md §1). Those machines run their
		// own old supervisor and never reach this line — but the rule they
		// encode is that "no profile" means spawn-and-say-so, not refuse, and a
		// current guest whose kernel cannot give it Landlock is a different
		// case that already refuses, in confineFail, with exit 126.
		return nil
	}
	if cmd.Err != nil {
		// Not a command at all — the lookup already failed. cmd.Start reports
		// that itself, which is what keeps not-found reading as not-found
		// rather than as a confinement failure.
		return nil
	}
	if !isConfineWrapper(cmd) {
		return fmt.Errorf("%w: %s", errNotConfined, cmd.Path)
	}
	return nil
}

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
