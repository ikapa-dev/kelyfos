package main

import (
	"errors"
	"os/exec"
	"slices"
	"testing"
)

// F8 (security review of 2026-08-28) — a binary the agent named after the
// confining helper ran unconfined, as root, as a child of PID 1.
//
// confine's re-entrancy guard tested a property of the *target*:
//
//	if strings.HasSuffix(cmd.Path, confineHelperMarker) { return }
//
// cmd.Path is the agent's own argv[0], resolved. The case the guard was written
// for — a command this function has already wrapped — has Path "/proc/self/exe",
// which never ends in the marker, so the guard never once fired for it. It fired
// for exactly one other case: a program whose path the agent chose. Two commands
// from inside an ordinary confined exec were the whole of it:
//
//	printf '#!/bin/sh\nmount -o remount,rw /\n' > /root/kelyfos-confine
//	chmod +x /root/kelyfos-confine && exec /root/kelyfos-confine
//
// /root is writable and executable under every flavor. argv[0] carries a
// separator, so exec.Command uses it verbatim; the guard matched; confine
// returned without rewriting anything; and cmd.Start() ran it with no Landlock
// domain and no seccomp filter. mount, reboot, module loading, the keyring calls
// and raw writes to /dev/vda and /dev/vdb — everything the profile exists to
// withhold — were back on the table for that process.
//
// A script rather than the `cp /bin/sh /root/kelyfos-confine` the review wrote:
// /bin/sh in this image is a symlink to BusyBox, which decides what to be from
// argv[0] and answers "applet not found" under any other name. What the guard
// read was the path, not the program, so the finding is unaffected — but the
// commands as published exit 127 without demonstrating it.
//
// The guard is now keyed on the wrapper's own identity, which is a thing the
// agent cannot name, and reaper.startAndRegister refuses to spawn a command the
// rewrite did not reach at all.

// withGuestProfile installs a profile for the duration of one test. The variable
// is package-level because there is one machine per supervisor; restoring it
// keeps a test that sets it from changing what every later test spawns.
func withGuestProfile(t *testing.T, flavor string) *Profile {
	t.Helper()
	saved := guestProfile
	t.Cleanup(func() { guestProfile = saved })
	p := profileFor(flavor)
	guestProfile = &p
	return &p
}

// wantWrapped asserts the whole of what confine must have left behind: the
// wrapper's path, the marker argv[0] a `ps` in the guest reads, the flavor, the
// resolved target, and the agent's original argv carried through untouched —
// BusyBox decides what to be from argv[0], so a wrapper that rewrote it would
// turn `sh` into something else.
func wantWrapped(t *testing.T, cmd *exec.Cmd, target string, argv []string) {
	t.Helper()
	if cmd.Path != "/proc/self/exe" {
		t.Fatalf("confine left %s to be started directly: cmd.Path is %q, not \"/proc/self/exe\".\n"+
			"  PID 1 would have forked and exec'd it with no Landlock domain and no seccomp filter.",
			target, cmd.Path)
	}
	if len(cmd.Args) == 0 || cmd.Args[0] != confineHelperMarker {
		t.Fatalf("the wrapped command's argv[0] is %q, not %q", cmd.Args, confineHelperMarker)
	}
	// The child parses its own argv with parseConfineArgs, so asserting through
	// it checks the two halves agree rather than checking one of them twice.
	flavor, path, gotArgv, err := parseConfineArgs(cmd.Args)
	if err != nil {
		t.Fatalf("confine produced an invocation its own parser rejects: %v", err)
	}
	if flavor != guestProfile.Name {
		t.Errorf("the wrapper was given flavor %q, not this machine's %q", flavor, guestProfile.Name)
	}
	if path != target {
		t.Errorf("the wrapper was told to exec %q, not %q", path, target)
	}
	if !slices.Equal(gotArgv, argv) {
		t.Errorf("the original argv was rewritten: got %q, want %q", gotArgv, argv)
	}
}

func TestF8_ConfineWrapsABinaryNamedLikeTheHelper(t *testing.T) {
	withGuestProfile(t, "dev")

	// The old guard matched a suffix of the whole path, so the names it handed
	// out are wider than the bare marker: any path ending in it did, in any
	// directory the profile makes writable and executable.
	for _, target := range []string{
		"/root/" + confineHelperMarker,
		"/tmp/evil-" + confineHelperMarker,
		"/work/build/" + confineHelperMarker,
		"/run/" + confineHelperMarker,
	} {
		t.Run(target, func(t *testing.T) {
			argv := []string{target, "-c", "mount -o remount,rw /"}
			cmd := exec.Command(argv[0], argv[1:]...)
			confine(cmd)
			wantWrapped(t, cmd, target, argv)
		})
	}
}

// The other half: an ordinary command is wrapped exactly as before. A fix that
// closed the hole by wrapping nothing would pass the test above.
func TestF8_ConfineStillWrapsAnOrdinaryCommand(t *testing.T) {
	withGuestProfile(t, "base")

	argv := []string{"/bin/sh", "-c", "echo hello"}
	cmd := exec.Command(argv[0], argv[1:]...)
	confine(cmd)
	wantWrapped(t, cmd, "/bin/sh", argv)
}

// A machine that resolved no profile confines nothing, and must still spawn.
// This is the pre-v0.9 image and the kernel-without-Landlock case; the ready
// frame says so and the host warns (D32).
func TestF8_ConfineIsANoOpWithNoProfile(t *testing.T) {
	saved := guestProfile
	t.Cleanup(func() { guestProfile = saved })
	guestProfile = nil

	cmd := exec.Command("/bin/sh", "-c", "echo hello")
	confine(cmd)
	if cmd.Path != "/bin/sh" {
		t.Errorf("with no profile resolved, confine rewrote the command anyway: %q", cmd.Path)
	}
}

// The replacement guard, keyed on the wrapper's identity rather than on a
// property of the target. Nothing constructs an already-wrapped command today —
// confine has one caller — so this is about the second caller somebody adds.
func TestF8_ConfineDoesNotWrapItsOwnWrapper(t *testing.T) {
	withGuestProfile(t, "dev")

	argv := []string{"/bin/sh", "-c", "echo hello"}
	cmd := exec.Command(argv[0], argv[1:]...)
	confine(cmd)
	once := slices.Clone(cmd.Args)
	confine(cmd)

	if !slices.Equal(cmd.Args, once) {
		t.Errorf("confine wrapped an already-wrapped command a second time:\n  once:  %q\n  twice: %q", once, cmd.Args)
	}
	// And the agent cannot reach that guard: exec.Command sets Args[0] from the
	// same string it resolves Path from, so a target it can name gives Args[0]
	// == the path, never the marker.
	unreachable := exec.Command("/proc/self/exe", "--confine", "dev", "--path", "/bin/sh", "--", "/bin/sh")
	confine(unreachable)
	if unreachable.Args[0] != confineHelperMarker {
		t.Errorf("a command the agent aimed at /proc/self/exe escaped the rewrite: %q", unreachable.Args)
	}
}

// The fail-closed half, which is the part that makes the hole impossible by
// construction rather than closed by example. confine is one function with three
// early returns in it, and whether any of them is reachable with a command the
// agent named is a question a reader has to answer again after every edit. This
// asserts that startAndRegister does not ask it: a command that is not the
// wrapper is not started, whatever confine did.
func TestF8_StartAndRegisterRefusesToSpawnAnUnconfinedCommand(t *testing.T) {
	withGuestProfile(t, "dev")
	rp := newReaper()

	// A command confine returns early on, standing in for whatever the next
	// early return turns out to be. It is deliberately one that would fail at
	// cmd.Start anyway: what is being asserted is that the refusal comes from
	// the invariant and comes *before* the fork, not that the fork failed.
	cmd := &exec.Cmd{Args: []string{"/root/" + confineHelperMarker, "-c", "mount -o remount,rw /"}}
	status, err := rp.startAndRegister(cmd)
	if !errors.Is(err, errNotConfined) {
		t.Fatalf("startAndRegister started a command the rewrite had not reached: status=%v err=%v", status, err)
	}
	if cmd.Process != nil {
		t.Errorf("and it forked: pid %d", cmd.Process.Pid)
	}
	if len(rp.waiters) != 0 {
		t.Errorf("and it registered a waiter for a process that does not exist: %v", rp.waiters)
	}
}

// The invariant on its own, over the cases startAndRegister cannot be driven
// into from a test — including the two that must NOT be refused.
func TestF8_ConfinementHoldsIsTheInvariantStartAndRegisterAsserts(t *testing.T) {
	p := profileFor("dev")

	// guestProfile is a package-level var and this sets it, so it is restored
	// on the way out (P7-17/C). The subtests below each save and restore it
	// around their own case; this line, outside them, did not — so every test
	// that ran after this one in the same binary inherited a dev profile it
	// never asked for. Nothing was wrong today because the tests that follow
	// set it themselves, which is exactly the kind of accident that stops being
	// true when somebody adds a test between them.
	savedProfile := guestProfile
	t.Cleanup(func() { guestProfile = savedProfile })

	wrapped := exec.Command("/bin/sh", "-c", "echo hello")
	guestProfile = &p
	confine(wrapped)

	notFound := exec.Command("definitely-not-a-command-kelyfos-f8")

	for _, tc := range []struct {
		name    string
		profile *Profile
		cmd     *exec.Cmd
		refuse  bool
	}{
		{"the wrapper itself", &p, wrapped, false},
		{"a command that never went through confine", &p, exec.Command("/bin/sh", "-c", "echo hello"), true},
		{"a binary named after the helper", &p, exec.Command("/root/" + confineHelperMarker), true},
		{"an empty path", &p, &exec.Cmd{Args: []string{"x"}}, true},
		{"a command that was not found", &p, notFound, false},
		{"a machine with no profile at all", nil, exec.Command("/bin/sh"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := guestProfile
			t.Cleanup(func() { guestProfile = saved })
			guestProfile = tc.profile

			err := confinementHolds(tc.cmd)
			switch {
			case tc.refuse && !errors.Is(err, errNotConfined):
				t.Errorf("this would have been spawned unconfined; confinementHolds said %v", err)
			case !tc.refuse && err != nil:
				t.Errorf("this must still be allowed to start; confinementHolds said %v", err)
			}
		})
	}
}

// A command that does not exist must still say so. dev/accept-profile.sh checks
// this from the outside — "not-found is still not-found, not a confinement
// failure" — and it is exactly what a fail-closed assertion written one line too
// early would break.
func TestF8_StartAndRegisterStillReportsNotFound(t *testing.T) {
	withGuestProfile(t, "dev")
	rp := newReaper()

	cmd := exec.Command("definitely-not-a-command-kelyfos-f8")
	_, err := rp.startAndRegister(cmd)
	if errors.Is(err, errNotConfined) {
		t.Fatalf("a missing command was reported as a confinement failure: %v", err)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("a missing command was not reported as not-found: %v", err)
	}
}
