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
	"mount", "umount2", "pivot_root", "chroot", "swapon", "swapoff",

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
