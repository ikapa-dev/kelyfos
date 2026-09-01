package main

// The refusal policy, by name, in one arch-independent list.
//
// Names rather than numbers, and shared rather than per-architecture, for two
// reasons. The policy is a statement about what an agent may ask the kernel
// for, and that statement does not change because the machine does. And
// `make docs` runs on whichever architecture CI happens to use, so a reference
// page generated from resolved numbers would differ between the dev machine and
// the runner and fail its own diff check for ever.
//
// The numbers live in profile_<arch>.go, which maps the names this architecture
// actually has. A name with no syscall here — settimeofday on aarch64, which
// has only clock_settime — is dropped from the compiled filter rather than
// faked, and `--dump-profile` prints it as absent so the difference is visible
// rather than silent.
//
// Nothing on this list is on an ordinary program's path. A compiler, a package
// manager and a test runner call none of them, which is what makes a refusal
// list safe where an allowlist would not be.
var refusalPolicy = []string{
	// The image is immutable and has no modules. The kernel config already
	// refuses these; refusing them here too means the guarantee does not rest
	// on one Kconfig line.
	"init_module", "finit_module", "delete_module",
	"kexec_load", "kexec_file_load",

	// The read-only root is a promise. A guest that can mount can lay a tmpfs
	// over /usr and hand the next command a different toolbox.
	//
	// The fd-based mount API (open_tree, move_mount, fsopen, fsconfig,
	// fsmount, fspick, mount_setattr) reaches the same ends without ever
	// calling mount — the audit of 2026-09-01 demonstrated open_tree(CLONE|
	// RECURSIVE) and fsopen("tmpfs") succeeding inside a guest whose map
	// predated that API (A5). Refusing the classic mount while leaving its
	// modern successors reachable was a refusal policy two syscall
	// generations behind the kernel's.
	//
	// fsconfig is in the list on its own evidence: the audit's report
	// misnumbered this API (it named fsmount 431, which is fsconfig's slot),
	// and the first probe run against the corrected filter came back EINVAL
	// — the kernel's own answer — rather than the filter's EPERM, which is
	// how the one name the audit and this file had both missed was found.
	// The numbers are resolved by the compiler from the kernel's own
	// constants; the probe is what keeps the policy honest.
	"mount", "umount2", "pivot_root", "chroot", "swapon", "swapoff",
	"open_tree", "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",

	// Only the supervisor powers this machine off, because a clean shutdown is
	// what makes a workspace write-back trustworthy (P2-1).
	"reboot",

	// The host owns the clock: it sets it at boot and again on every snapshot
	// restore (P3-1), and every event in the flight recorder is stamped against
	// it. A guest that moves its own clock corrupts the audit timeline, which
	// is the one artefact this product sells.
	"clock_settime", "clock_adjtime", "adjtimex", "settimeofday",

	// Namespaces, keyrings and handle-based opens: the classic escape surface,
	// and unreachable from anything this image ships.
	"setns", "unshare", "add_key", "request_key", "keyctl", "open_by_handle_at",

	// The cross-memory and fd-theft family. Every ptrace-shaped attack on the
	// supervisor failed at the kernel ACL during the 2026-09-01 audit — and
	// the audit's own point stands: that safety rests on an ACL, not on this
	// policy, and a kernel or LSM change away from re-exposure is one rebuild
	// nobody would make. Refusing them by name is the second, independent
	// refusal, and it costs nothing: no process this supervisor spawns has
	// business reading another process's memory or stealing its fds (A5,
	// A17b).
	"process_vm_readv", "process_vm_writev",
	"pidfd_open", "pidfd_getfd", "pidfd_send_signal",

	// Kernel interfaces with a long history and no use here. bpf and
	// perf_event_open are compiled out of the guest kernel; acct, quotactl and
	// syslog are not.
	"bpf", "perf_event_open", "acct", "quotactl", "syslog",

	// Last, because it is the one entry a flavor may take back out.
	"ptrace",
}

// deniedSyscalls resolves the policy against this architecture.
func deniedSyscalls() []syscallRef {
	out := make([]syscallRef, 0, len(refusalPolicy))
	for _, name := range refusalPolicy {
		nr, ok := syscallNumbers[name]
		if !ok {
			// Not a syscall on this architecture. Recorded with -1 so the dump
			// can say so; the filter skips it.
			out = append(out, syscallRef{name: name, nr: -1})
			continue
		}
		out = append(out, syscallRef{name: name, nr: nr})
	}
	return out
}
