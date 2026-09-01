//go:build linux && amd64

package main

import "golang.org/x/sys/unix"

// auditArch is AUDIT_ARCH_X86_64 (include/uapi/linux/audit.h). A seccomp filter that
// does not pin the architecture can be walked past on a machine that runs more
// than one ABI.
const auditArch = 0xc000003e

// syscallNumbers maps the refusal policy's names to this architecture's numbers,
// resolved by the compiler from the kernel's own constants rather than from a
// table kept here. A name the policy lists and this architecture does not have
// is simply absent.
var syscallNumbers = map[string]int{
	"init_module":     unix.SYS_INIT_MODULE,
	"finit_module":    unix.SYS_FINIT_MODULE,
	"delete_module":   unix.SYS_DELETE_MODULE,
	"kexec_load":      unix.SYS_KEXEC_LOAD,
	"kexec_file_load": unix.SYS_KEXEC_FILE_LOAD,
	"mount":           unix.SYS_MOUNT,
	"umount2":         unix.SYS_UMOUNT2,
	"pivot_root":      unix.SYS_PIVOT_ROOT,
	"chroot":          unix.SYS_CHROOT,
	"swapon":          unix.SYS_SWAPON,
	"swapoff":         unix.SYS_SWAPOFF,
	// The fd-based mount API (audit 2026-09-01, A5). x86_64 takes the
	// asm-generic numbers from 424 up, the same aarch64 does — but the
	// compiler, not this comment, is what keeps the numbers honest. fsconfig
	// sits at 431, between fsopen and fsmount, and its absence from the
	// audit's own list is how the first probe run found it (its probe of 431
	// came back EINVAL, the kernel's, not the filter's EPERM).
	"open_tree":         unix.SYS_OPEN_TREE,
	"move_mount":        unix.SYS_MOVE_MOUNT,
	"fsopen":            unix.SYS_FSOPEN,
	"fsconfig":          unix.SYS_FSCONFIG,
	"fsmount":           unix.SYS_FSMOUNT,
	"fspick":            unix.SYS_FSPICK,
	"mount_setattr":     unix.SYS_MOUNT_SETATTR,
	"reboot":            unix.SYS_REBOOT,
	"clock_settime":     unix.SYS_CLOCK_SETTIME,
	"clock_adjtime":     unix.SYS_CLOCK_ADJTIME,
	"adjtimex":          unix.SYS_ADJTIMEX,
	"setns":             unix.SYS_SETNS,
	"unshare":           unix.SYS_UNSHARE,
	"add_key":           unix.SYS_ADD_KEY,
	"request_key":       unix.SYS_REQUEST_KEY,
	"keyctl":            unix.SYS_KEYCTL,
	"open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
	// The cross-memory and fd-theft family (A5, A17b).
	"process_vm_readv":  unix.SYS_PROCESS_VM_READV,
	"process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
	"pidfd_open":        unix.SYS_PIDFD_OPEN,
	"pidfd_getfd":       unix.SYS_PIDFD_GETFD,
	"pidfd_send_signal": unix.SYS_PIDFD_SEND_SIGNAL,
	"bpf":               unix.SYS_BPF,
	"perf_event_open":   unix.SYS_PERF_EVENT_OPEN,
	"acct":              unix.SYS_ACCT,
	"quotactl":          unix.SYS_QUOTACTL,
	"syslog":            unix.SYS_SYSLOG,
	"ptrace":            unix.SYS_PTRACE,
	"settimeofday":      unix.SYS_SETTIMEOFDAY,
}
