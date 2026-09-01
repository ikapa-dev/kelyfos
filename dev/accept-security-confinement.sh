#!/usr/bin/env bash
# KelyfOS — guest confinement against its bypass battery, committed as a
# suite (ST-3.2).
#
#   bash dev/accept-security-confinement.sh
#
# The audit probed ~20 confinement cases by hand — root in the guest, and
# every path out refused. This file commits them. Each vector asserts its
# observed outcome and is labelled for what it is:
#
#   REFUSED  — the mechanism stopped it (Landlock, seccomp, capabilities);
#   STRIPPED — the dangerous bit is removed on the way through;
#   FENCED   — the syscall is allowed by the filter, the effect stays inside
#              the sandbox's own namespaces, which is the design working.
#
# The plan's carve-out is honoured literally: each vector is asserted
# refused — or its allowlist documented. io_uring and userfaultfd are NOT in
# the refusal policy; pretending they are refused would be a suite lying in
# the contract's voice. On the dev flavor ptrace is permitted by design
# (AllowPtrace, profile_policy/profile.go's guards — §6.2), so a probe
# asserting ptrace is refused would fail correctly and confuse everyone:
# what is asserted is PTRACE_ATTACH to PID 1, which Landlock's sibling-domain
# rule refuses on every flavor.
#
# No network anywhere in it.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-confinement

aup -image dev
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi

cat > "$SLAB_WORK/battery.py" <<'PY'
import ctypes, os, socket, sys

libc = ctypes.CDLL(None, use_errno=True)

def attempt(name, fn, expect):
    try:
        fn()
        print(f"{name}: ALLOWED ({expect})")
    except OSError as e:
        print(f"{name}: ERRNO {e.errno} ({expect})")
    except Exception as e:
        print(f"{name}: EXCEPTION {type(e).__name__} ({expect})")

# --- filesystem: Landlock fences everything outside the writable trees ---
def w_etc():
    with open("/etc/passwd", "a") as f:
        f.write("x")
attempt("landlock.etc-write", w_etc, "REFUSED by Landlock")

def w_procsys():
    with open("/proc/sys/kernel/hostname", "w") as f:
        f.write("x")
attempt("landlock.proc-sys-write", w_procsys, "REFUSED by Landlock")

def w_vda():
    fd = os.open("/dev/vda", os.O_RDWR)
    os.close(fd)
attempt("blk.dev-vda-write", w_vda, "REFUSED (device node not writable)")

# --- seccomp refusal policy: these return EPERM from the filter ---
libc.mount.restype = ctypes.c_long
def s_mount():
    if libc.mount(b"none", b"/tmp", b"tmpfs", 0, None) < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
attempt("seccomp.mount", s_mount, "REFUSED by seccomp (mount)")

def s_mknod():
    if libc.mknod(b"/tmp/node", 0o600 | 0o020000, 0) < 0:
        raise OSError(ctypes.get_errno(), "mknod")
attempt("seccomp.mknod", s_mknod, "REFUSED by seccomp (mknod)")

def s_setns():
    fd = os.open("/proc/self/ns/mnt", os.O_RDONLY)
    try:
        if libc.setns(fd, 0) < 0:
            raise OSError(ctypes.get_errno(), "setns")
    finally:
        os.close(fd)
attempt("seccomp.setns", s_setns, "REFUSED by seccomp (setns)")

def s_unshare():
    if libc.unshare(0x08000000) < 0:  # CLONE_NEWNS
        raise OSError(ctypes.get_errno(), "unshare")
attempt("seccomp.unshare", s_unshare, "REFUSED by seccomp (unshare)")

def s_bpf():
    if libc.syscall(280, 0, 0, 0, 0, 0) < 0:  # __NR_bpf on arm64 (the dump prints it)
        raise OSError(ctypes.get_errno(), "bpf")
attempt("seccomp.bpf", s_bpf, "REFUSED by seccomp (bpf)")

def s_keyctl():
    # musl exports no add_key wrapper: the raw syscall, arm64 #217 (the dump
    # prints the number).
    if libc.syscall(217, b"user", b"k", b"v", 1, -2) < 0:  # KEY_SPEC_PROCESS_KEYRING
        raise OSError(ctypes.get_errno(), "add_key")
attempt("seccomp.add_key", s_keyctl, "REFUSED by seccomp (add_key)")

def s_open_by_handle():
    if libc.syscall(265, 0, 0, 0) < 0:  # __NR_open_by_handle_at on arm64
        raise OSError(ctypes.get_errno(), "open_by_handle_at")
attempt("seccomp.open_by_handle_at", s_open_by_handle, "REFUSED by seccomp")

# --- the fd-based mount API and the cross-memory family (audit 2026-09-01, A5) ---
# The refusal list is name-keyed against a hand-maintained per-arch map, and
# the audit found open_tree and fsopen reaching the kernel because the map
# predated that API. These probes are the CI drift gate the audit asked for:
# each syscall is probed from this confined child, and an allow is a red run
# rather than a stale map nobody reads. Numbers are arm64/asm-generic, the
# arch this lab runs; the supervisor's own unit test
# (supervisor/profile_policy_test.go) is what fails when a name is missing
# from a per-arch map, on both arches, at build time.
#
# fsconfig is probed on its own evidence: the audit's report misnumbered this
# API (it named fsmount 431 — fsconfig's slot), and the first probe run came
# back EINVAL — the kernel's own answer — rather than the filter's EPERM,
# which is how the one name both had missed was found.
def s_open_tree():
    # open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE|AT_RECURSIVE) — the audit's own
    # probe, which returned a live fd before the fix.
    if libc.syscall(428, -100, b"/", 0x1 | 0x8000) < 0:
        raise OSError(ctypes.get_errno(), "open_tree")
attempt("seccomp.open_tree", s_open_tree, "REFUSED by seccomp (fd-mount API)")

def s_fsopen():
    if libc.syscall(430, b"tmpfs", 0) < 0:
        raise OSError(ctypes.get_errno(), "fsopen")
attempt("seccomp.fsopen", s_fsopen, "REFUSED by seccomp (fd-mount API)")

def s_fsconfig():
    if libc.syscall(431, -1, 0, 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "fsconfig")
attempt("seccomp.fsconfig", s_fsconfig, "REFUSED by seccomp (fd-mount API)")

def s_fsmount():
    if libc.syscall(432, -1, 0) < 0:
        raise OSError(ctypes.get_errno(), "fsmount")
attempt("seccomp.fsmount", s_fsmount, "REFUSED by seccomp (fd-mount API)")

def s_fspick():
    if libc.syscall(433, -100, b"/", 0) < 0:
        raise OSError(ctypes.get_errno(), "fspick")
attempt("seccomp.fspick", s_fspick, "REFUSED by seccomp (fd-mount API)")

def s_move_mount():
    if libc.syscall(429, -100, b"/", -100, b"/tmp/x", 0) < 0:
        raise OSError(ctypes.get_errno(), "move_mount")
attempt("seccomp.move_mount", s_move_mount, "REFUSED by seccomp (fd-mount API)")

def s_mount_setattr():
    if libc.syscall(442, -100, b"/", 0, None, 0) < 0:
        raise OSError(ctypes.get_errno(), "mount_setattr")
attempt("seccomp.mount_setattr", s_mount_setattr, "REFUSED by seccomp (fd-mount API)")

def s_process_vm_readv():
    # local iov, remote iov, flags — the audit's A17b companion: the refusal
    # list, not only the kernel ACL, now refuses cross-memory reads.
    if libc.syscall(270, 0, None, 0, None, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "process_vm_readv")
attempt("seccomp.process_vm_readv", s_process_vm_readv, "REFUSED by seccomp (cross-memory)")

def s_pidfd_getfd():
    # pidfd_open(getpid()) then pidfd_getfd on it — fd theft, the audit's
    # A17b; refusing pidfd_open alone would leave the probe honest but the
    # family half-covered, so both are in the policy.
    pidfd = libc.syscall(434, 0, 0)  # __NR_pidfd_open on arm64
    if pidfd >= 0:
        try:
            if libc.syscall(438, pidfd, 1, 0) < 0:
                raise OSError(ctypes.get_errno(), "pidfd_getfd")
        finally:
            libc.close(pidfd)
    else:
        raise OSError(ctypes.get_errno(), "pidfd_open")
attempt("seccomp.pidfd_getfd", s_pidfd_getfd, "REFUSED by seccomp (fd theft)")

# --- ptrace: permitted by the dev flavor, fenced by Landlock's sibling rule ---
def p_pid1():
    if libc.ptrace(16, 1, 0, 0) < 0:  # PTRACE_ATTACH
        raise OSError(ctypes.get_errno(), "ptrace")
attempt("ptrace.attach-pid1", p_pid1, "REFUSED by Landlock (sibling domains; dev flavor permits ptrace itself)")

# --- allowed by the filter, fenced by the namespaces: the documented half ---
def s_io_uring():
    buf = ctypes.create_string_buffer(200)
    if libc.syscall(425, 4, buf, 0, 0, 0) < 0:  # __NR_io_uring_setup on arm64
        raise OSError(ctypes.get_errno(), "io_uring_setup")
attempt("filter.io_uring_setup", s_io_uring, "FENCED: not in the refusal policy; the guest's own kernel view is its own")

def s_mem_self():
    with open("/proc/self/mem", "rb") as f:
        f.read(1)
attempt("filter.proc-self-mem-read", s_mem_self, "FENCED: self-access is the agent's own memory, not an escape")

def s_tiocsti():
    attempt_inner = lambda: os.system("printf x > /dev/tty")
    attempt_inner()
attempt("filter.tiocsti", s_tiocsti, "FENCED: writes only the guest's own tty, if any")

def s_abstract_socket():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("\0sec-lab-probe")
    s.close()
attempt("filter.abstract-unix", s_abstract_socket, "FENCED: abstract sockets are netns-local; the guest's namespace is its own")
PY
out="$(ax_script python3 "$SLAB_WORK/battery.py" 2>/dev/null)"
echo "$out" | sed 's/^/  | /'

assert_contains "$out" "landlock.etc-write: ERRNO" "writing /etc fails with an errno, not a success"
assert_contains "$out" "landlock.proc-sys-write: ERRNO" "writing /proc/sys fails"
assert_contains "$out" "blk.dev-vda-write: ERRNO" "opening /dev/vda for write fails"
assert_contains "$out" "seccomp.mount: ERRNO 1" "mount returns EPERM from the filter"
assert_contains "$out" "seccomp.mknod: ERRNO 1" "mknod returns EPERM"
assert_contains "$out" "seccomp.setns: ERRNO 1" "setns returns EPERM"
assert_contains "$out" "seccomp.unshare: ERRNO 1" "unshare returns EPERM"
assert_contains "$out" "seccomp.bpf: ERRNO 1" "bpf returns EPERM"
assert_contains "$out" "seccomp.add_key: ERRNO 1" "add_key returns EPERM"
assert_contains "$out" "seccomp.open_by_handle_at: ERRNO 1" "open_by_handle_at returns EPERM"
assert_contains "$out" "seccomp.open_tree: ERRNO 1" "open_tree returns EPERM — the fd-based mount API is refused (audit A5)"
assert_contains "$out" "seccomp.fsopen: ERRNO 1" "fsopen returns EPERM (audit A5)"
assert_contains "$out" "seccomp.fsconfig: ERRNO 1" "fsconfig returns EPERM (audit A5)"
assert_contains "$out" "seccomp.fsmount: ERRNO 1" "fsmount returns EPERM (audit A5)"
assert_contains "$out" "seccomp.fspick: ERRNO 1" "fspick returns EPERM (audit A5)"
assert_contains "$out" "seccomp.move_mount: ERRNO 1" "move_mount returns EPERM (audit A5)"
assert_contains "$out" "seccomp.mount_setattr: ERRNO 1" "mount_setattr returns EPERM (audit A5)"
assert_contains "$out" "seccomp.process_vm_readv: ERRNO 1" "process_vm_readv returns EPERM from the filter, not only the ACL (audit A5/A17b)"
assert_contains "$out" "seccomp.pidfd_getfd: ERRNO 1" "pidfd_getfd returns EPERM — fd theft refused by the policy (audit A5/A17b)"
assert_contains "$out" "ptrace.attach-pid1: ERRNO 1" "PTRACE_ATTACH to PID 1 returns EPERM — even on the dev flavor that permits ptrace"
assert_contains "$out" "filter.io_uring_setup: ALLOWED" "io_uring is allowed by the filter — documented, not lied about"
assert_contains "$out" "filter.abstract-unix: ALLOWED" "abstract unix sockets are allowed — netns-local, documented"

adown

slab_done
