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

# musl exports no wrapper for most of what this battery probes, so the raw
# syscall(2) is the only way to reach them — and a raw number is arch-specific.
# That is the whole shape of the audit of 2026-09-01 (A5/M8): the supervisor's
# refusal policy is a per-arch name->number map, and a name absent from it is
# dropped from the compiled filter silently. This battery keeps its own map,
# per-arch, so it probes the same numbers on whatever arch the guest is — and
# every probe is written so that if the filter missed the syscall the kernel's
# own answer (EINVAL, EBADF) would come back instead of the filter's EPERM,
# which is the drift signal a stale map would show.
#
# ARCH_NR holds the legacy numbers that differ between ABIs; SHARED holds the
# asm-generic range (>= 424) x86_64 and aarch64 number identically. NR is the
# merge the probes index by name.
m = os.uname().machine
ARCH_NR = {
    "aarch64": {
        "bpf": 280, "add_key": 217, "open_by_handle_at": 265,
        "process_vm_readv": 270, "process_vm_writev": 271,
    },
    "x86_64": {
        "bpf": 321, "add_key": 248, "open_by_handle_at": 304,
        "process_vm_readv": 310, "process_vm_writev": 311,
    },
}
SHARED = {
    "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431,
    "fsmount": 432, "fspick": 433, "mount_setattr": 442,
    "pidfd_send_signal": 424, "pidfd_open": 434, "pidfd_getfd": 438,
    "io_uring_setup": 425,
}
if m not in ARCH_NR:
    print(f"battery: no syscall table for {m}")
    sys.exit(3)
print(f"battery: arch {m} table")
NR = dict(SHARED)
NR.update(ARCH_NR[m])

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
    if libc.syscall(NR["bpf"], 0, 0, 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "bpf")
attempt("seccomp.bpf", s_bpf, "REFUSED by seccomp (bpf)")

def s_keyctl():
    # musl exports no add_key wrapper: the raw syscall, numbered per arch.
    if libc.syscall(NR["add_key"], b"user", b"k", b"v", 1, -2) < 0:  # KEY_SPEC_PROCESS_KEYRING
        raise OSError(ctypes.get_errno(), "add_key")
attempt("seccomp.add_key", s_keyctl, "REFUSED by seccomp (add_key)")

def s_open_by_handle():
    if libc.syscall(NR["open_by_handle_at"], 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "open_by_handle_at")
attempt("seccomp.open_by_handle_at", s_open_by_handle, "REFUSED by seccomp")

# --- the fd-based mount API and the cross-memory family (audit 2026-09-01, A5) ---
# The refusal list is name-keyed against a hand-maintained per-arch map, and
# the audit found open_tree and fsopen reaching the kernel because the map
# predated that API. These probes are the CI drift gate the audit asked for:
# each of the twelve names is probed by its own number from this confined
# child, and an allow is a red run rather than a stale map nobody reads. The
# numbers come from NR, per-arch, so the same probes run on aarch64 and on
# x86_64; the supervisor's own unit test
# (supervisor/profile_policy_test.go) is what fails when a name is missing
# from a per-arch map, on both arches, at build time.
#
# fsconfig is probed on its own evidence: the audit's report misnumbered this
# API (it named fsmount 431 — fsconfig's slot), and the first probe run came
# back EINVAL — the kernel's own answer — rather than the filter's EPERM,
# which is how the one name both had missed was found. Every probe below
# keeps that property: a bogus fd or an invalid flag, so a kernel that saw the
# call would answer EBADF or EINVAL and only the filter answers EPERM.
def s_open_tree():
    # open_tree(AT_FDCWD, "/", OPEN_TREE_CLONE|AT_RECURSIVE) — the audit's own
    # probe, which returned a live fd before the fix.
    if libc.syscall(NR["open_tree"], -100, b"/", 0x1 | 0x8000) < 0:
        raise OSError(ctypes.get_errno(), "open_tree")
attempt("seccomp.open_tree", s_open_tree, "REFUSED by seccomp (fd-mount API)")

def s_fsopen():
    if libc.syscall(NR["fsopen"], b"tmpfs", 0) < 0:
        raise OSError(ctypes.get_errno(), "fsopen")
attempt("seccomp.fsopen", s_fsopen, "REFUSED by seccomp (fd-mount API)")

def s_fsconfig():
    if libc.syscall(NR["fsconfig"], -1, 0, 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "fsconfig")
attempt("seccomp.fsconfig", s_fsconfig, "REFUSED by seccomp (fd-mount API)")

def s_fsmount():
    if libc.syscall(NR["fsmount"], -1, 0) < 0:
        raise OSError(ctypes.get_errno(), "fsmount")
attempt("seccomp.fsmount", s_fsmount, "REFUSED by seccomp (fd-mount API)")

def s_fspick():
    if libc.syscall(NR["fspick"], -100, b"/", 0) < 0:
        raise OSError(ctypes.get_errno(), "fspick")
attempt("seccomp.fspick", s_fspick, "REFUSED by seccomp (fd-mount API)")

def s_move_mount():
    if libc.syscall(NR["move_mount"], -100, b"/", -100, b"/tmp/x", 0) < 0:
        raise OSError(ctypes.get_errno(), "move_mount")
attempt("seccomp.move_mount", s_move_mount, "REFUSED by seccomp (fd-mount API)")

def s_mount_setattr():
    if libc.syscall(NR["mount_setattr"], -100, b"/", 0, None, 0) < 0:
        raise OSError(ctypes.get_errno(), "mount_setattr")
attempt("seccomp.mount_setattr", s_mount_setattr, "REFUSED by seccomp (fd-mount API)")

def s_process_vm_readv():
    # local iov, remote iov, flags — the cross-memory read the audit's A17b
    # class rests on. The refusal list, not only the kernel ACL, refuses it.
    if libc.syscall(NR["process_vm_readv"], 0, None, 0, None, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "process_vm_readv")
attempt("seccomp.process_vm_readv", s_process_vm_readv, "REFUSED by seccomp (cross-memory)")

def s_process_vm_writev():
    # pid -1, flags 1 — flags must be 0, so an unfiltered kernel answers EINVAL
    # and only the filter answers EPERM. The write half of the cross-memory
    # family, probed on its own number rather than assumed from the read (M8).
    if libc.syscall(NR["process_vm_writev"], -1, None, 0, None, 0, 1) < 0:
        raise OSError(ctypes.get_errno(), "process_vm_writev")
attempt("seccomp.process_vm_writev", s_process_vm_writev, "REFUSED by seccomp (cross-memory)")

def s_pidfd_open():
    # pid 0 is not a valid target, so an unfiltered kernel answers EINVAL; a
    # probe by number rather than behind another call, so a missing 434 shows.
    if libc.syscall(NR["pidfd_open"], 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "pidfd_open")
attempt("seccomp.pidfd_open", s_pidfd_open, "REFUSED by seccomp (fd theft)")

def s_pidfd_getfd():
    # 438 probed directly with a bogus pidfd (-1). Behind pidfd_open the probe
    # printed EPERM whether or not 438 was mapped, because pidfd_open is refused
    # first (audit 2026-09-01, M8) — so a drop of 438 alone stayed green. A
    # direct call is EBADF from an unfiltered kernel and EPERM from the filter.
    if libc.syscall(NR["pidfd_getfd"], -1, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "pidfd_getfd")
attempt("seccomp.pidfd_getfd", s_pidfd_getfd, "REFUSED by seccomp (fd theft)")

def s_pidfd_send_signal():
    # bogus pidfd (-1): an unfiltered kernel answers EBADF, the filter EPERM.
    if libc.syscall(NR["pidfd_send_signal"], -1, 0, None, 0) < 0:
        raise OSError(ctypes.get_errno(), "pidfd_send_signal")
attempt("seccomp.pidfd_send_signal", s_pidfd_send_signal, "REFUSED by seccomp (fd theft)")

# --- ptrace: permitted by the dev flavor, fenced by Landlock's sibling rule ---
def p_pid1():
    if libc.ptrace(16, 1, 0, 0) < 0:  # PTRACE_ATTACH
        raise OSError(ctypes.get_errno(), "ptrace")
attempt("ptrace.attach-pid1", p_pid1, "REFUSED by Landlock (sibling domains; dev flavor permits ptrace itself)")

# --- allowed by the filter, fenced by the namespaces: the documented half ---
def s_io_uring():
    buf = ctypes.create_string_buffer(200)
    if libc.syscall(NR["io_uring_setup"], 4, buf, 0, 0, 0) < 0:
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

# First: the battery found a per-arch table for the guest it ran in. Without
# this the twelve seccomp.* probes below would be probing numbers for an arch
# the guest is not, and an unknown arch exits the battery 3 with no table.
assert_contains "$out" "battery: arch" "the battery selected a per-arch syscall table for the guest"
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
assert_contains "$out" "seccomp.process_vm_writev: ERRNO 1" "process_vm_writev returns EPERM — the write half of the cross-memory family (audit A5/M8)"
assert_contains "$out" "seccomp.pidfd_open: ERRNO 1" "pidfd_open returns EPERM from the filter (audit A5/M8)"
assert_contains "$out" "seccomp.pidfd_getfd: ERRNO 1" "pidfd_getfd returns EPERM — 438 probed directly, not behind pidfd_open (audit A5/M8)"
assert_contains "$out" "seccomp.pidfd_send_signal: ERRNO 1" "pidfd_send_signal returns EPERM from the filter (audit A5/M8)"
assert_contains "$out" "ptrace.attach-pid1: ERRNO 1" "PTRACE_ATTACH to PID 1 returns EPERM — even on the dev flavor that permits ptrace"
assert_contains "$out" "filter.io_uring_setup: ALLOWED" "io_uring is allowed by the filter — documented, not lied about"
assert_contains "$out" "filter.abstract-unix: ALLOWED" "abstract unix sockets are allowed — netns-local, documented"

adown

slab_done
