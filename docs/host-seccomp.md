# The host syscall filter — which one, proved, and what it permits

*The wall around the VMM process on the host. Not the guest: what an agent may
ask its own kernel for is [`docs/hardening.md`](hardening.md) §4. This page is
about what Firecracker itself may ask the host kernel for, which is the layer
that matters if the VM boundary ever fails.*

*Everything here was read out of a running machine. Where a number appears, it
came from `/proc` or from the program the kernel handed back, not from
documentation about either.*

---

## The short version

Firecracker compiles a seccomp allowlist into its own release binary and
installs it on every thread during startup. KelyfOS does not write that filter,
does not replace it, and does not turn it off — and from v0.9 it refuses to run
a VMM that came up without one.

| | |
| --- | --- |
| whose filter | Firecracker's own, compiled into the binary `versions.mk` pins |
| how many | three distinct programs — one for the VMM thread, one for the API thread, one shared by the vcpu threads |
| what it does with a syscall on no list | `SECCOMP_RET_TRAP` — `SIGSYS`, and the process dies |
| what it does with a syscall from another architecture | `SECCOMP_RET_KILL_THREAD` |
| if it is absent | the run is refused with `[seccomp.not_in_force]` |

---

## 1. Which filter

Firecracker's build compiles `resources/seccomp/<target-triple>.json` into a
binary blob and embeds it in the executable, and `main` installs it unless told
otherwise. There are exactly two ways to be running something else:

- `--no-seccomp`, which installs nothing at all — and, because the filter
  installation is also what sets `PR_SET_NO_NEW_PRIVS`, silently costs that too;
- `--seccomp-filter <path>`, which replaces it with a program from a file.
  Firecracker's own documentation warns that a misconfigured one can "disable the
  seccomp security boundary altogether".

KelyfOS passes neither, anywhere. That is the whole argument for *which* filter
is in force, so it is worth saying where it could break. The jailer forwards
everything after `--` to Firecracker verbatim, which makes the tail of
`jailArgv` the one place in this codebase either flag could reach the VMM.
`internal/sandbox/jail_test.go` asserts that tail carries neither, on the cold
boot path, the restore path and the cgroup path — with no KVM and no root, so it
runs on every commit rather than only where a VM can boot.

The filter's identity is therefore the binary's identity, and the binary is
pinned: `versions.mk` names the Firecracker release and
`dev/install-firecracker.sh` verifies its published sha256 before installing it.
A different Firecracker is a different filter, and the acceptance notices,
because the program's own fingerprint is part of the record below.

**The jailer does not come into it.** It installs no filter and removes none;
Firecracker installs its own after the jailer execs into it. `--no-jail` changes
which walls are around the VMM but not this one.

## 2. That it is on

`kelyfos` reads `/proc/<tid>/status` for **every thread** of the VMM once the
guest is answering, and refuses the run if any of them is not in
`SECCOMP_MODE_FILTER`.

Per thread rather than per process, because Firecracker installs its filters
without `SECCOMP_FILTER_FLAG_TSYNC`: each thread carries its own, and a
process-level read cannot see a single unfiltered one. Once the guest has
answered, all of them are installed — the vcpu threads filter themselves before
executing any guest code, the API thread before it serves, and the VMM thread
last of all, before the vcpus are resumed.

The read happens after boot-to-ready is recorded, so the numbers in the README
measure the machine and not the checking of it.

What a run prints, and what its `sandbox.json` keeps:

```
  jail        chroot, uid 501, /home/you/.cache/kelyfos/run/firecracker/<id>/root
  seccomp     filter mode, read from /proc on all 4 VMM threads
```

A machine whose Firecracker was built in debug, or for a target with no filter
file, ships an empty filter and installs nothing. That is a real state a real
machine can be in, so it is refused rather than run:

```
Firecracker is running without its syscall filter (fc_vcpu 0 (tid 41207) reports
Seccomp: 0) [seccomp.not_in_force]
    install an official Firecracker release — bash dev/install-firecracker.sh —
    because the filter is built into that binary, and a debug build or an
    unsupported target ships an empty one that installs nothing
```

`dev/accept-seccomp.sh` proves that refusal fires by causing it: a wrapper on
`PATH` that appends `--no-seccomp` really does start a VMM with no filter, and
the run must refuse and tear it down. A check that can only ever pass is not a
check.

## 3. What it permits

The lists below were not transcribed from Firecracker's JSON. `dev/seccomp-probe`
attaches to the VMM with `ptrace`, pulls the installed classic-BPF program back
out with `PTRACE_SECCOMP_GET_FILTER`, and interprets it: for each syscall number
in turn, with `nr` and `arch` fixed and every argument left unknown, which return
actions can the program reach?

That last part is why there are two columns. A comparison against an unknown
value has to take both branches, so a syscall the filter allows only for certain
arguments reports both the allow and the trap as reachable and lands in
**conditional** — it is never quietly promoted to "allowed" or demoted to
"refused". `ioctl` is the clearest case: the filter permits a specific list of
request numbers, mostly KVM's, and traps every other `ioctl` in existence.

They do agree with the published JSON, which is the point of doing it this way:
two independent sources, one answer. For aarch64 at v1.16.1 the file lists 50
distinct syscalls for `vmm`, 31 for `api` and 24 for `vcpu`, and so does the
program in the kernel.

The exact, machine-checked copy lives in `dev/expect/host-seccomp-<arch>.txt`,
and the acceptance diffs a live VMM against it. This page is written from those
files; if they ever disagree, the files are the record.

### aarch64

Firecracker v1.16.1. VMM program 179 instructions
(`e2b10f5c74d68cb1…`), API 103 (`830d937c12514838…`), vcpu 103
(`477f0d1c9c0266b7…`).

| thread | allowed outright | allowed only for some arguments |
| --- | --- | --- |
| **vmm** (37 + 13) | `brk` `clock_gettime` `close` `connect` `epoll_ctl` `epoll_pwait` `eventfd2` `exit` `exit_group` `fstat` `fsync` `ftruncate` `getrandom` `gettid` `io_uring_enter` `io_uring_register` `io_uring_setup` `lseek` `madvise` `mincore` `mremap` `munmap` `newfstatat` `openat` `read` `readv` `recvfrom` `recvmsg` `restart_syscall` `rt_sigprocmask` `rt_sigreturn` `sched_yield` `sendmsg` `sendto` `sigaltstack` `write` `writev` | `accept4` `fcntl` `futex` `ioctl` `memfd_create` `mmap` `mprotect` `msync` `rt_sigaction` `socket` `timerfd_create` `timerfd_settime` `tkill` |
| **api** (22 + 9) | `brk` `clock_gettime` `close` `epoll_ctl` `epoll_pwait` `exit` `exit_group` `fstat` `getrandom` `gettid` `mremap` `munmap` `openat` `read` `recvfrom` `recvmsg` `restart_syscall` `rt_sigprocmask` `sched_yield` `sendto` `sigaltstack` `write` | `accept4` `fcntl` `futex` `ioctl` `madvise` `mmap` `rt_sigaction` `socket` `tkill` |
| **vcpu** (17 + 7) | `brk` `clock_gettime` `close` `exit` `exit_group` `fstat` `gettid` `mremap` `munmap` `openat` `restart_syscall` `rt_sigprocmask` `rt_sigreturn` `sched_yield` `sendmsg` `sigaltstack` `write` | `futex` `ioctl` `madvise` `mmap` `rt_sigaction` `timerfd_settime` `tkill` |

Worth reading twice, and all of it from the table above: there is no `execve`,
no `fork`, no `clone`, no `ptrace`, no `chmod`, no `unlink`, no `bind` and no
`listen` on any of the three. The vcpu threads cannot `read` at all.

The *conditions* on the right-hand column are a second question, and the probe
does not answer it — it reports that a syscall's permission depends on its
arguments, not on which. For those, Firecracker's published
`resources/seccomp/aarch64-unknown-linux-musl.json` for this release is the
source, and the ones worth knowing are: `socket` only for `AF_UNIX` +
`SOCK_STREAM|SOCK_CLOEXEC`; `mmap` and `mprotect` only with `PROT_EXEC` clear;
`tkill` only for `SIGABRT` and the vcpu signal; `ioctl` only for a named list of
requests, almost all of them KVM's, with `TUNSETIFF` and two `TUN` offload
requests on the VMM thread because that is how a TAP device is opened for
`--allow`.

### x86_64

Recorded on the bare-KVM reference (D15), which is the only place a real x86_64
VMM runs. Firecracker v1.16.1. VMM program 182 instructions
(`5fccc87ef16d5e8b…`), API 105 (`6c84e6903a75ecda…`), vcpu 106
(`2ae943f46cd3e7c4…`).

The permitted **sets** differ from aarch64 in exactly two syscalls, both of them
the same syscall wearing a different name: `open` and `stat` where aarch64 has
`openat` and `newfstatat`. Everything else — all three allowed lists, all three
conditional lists — is identical name for name.

| thread | allowed outright | allowed only for some arguments |
| --- | --- | --- |
| **vmm** (37 + 13) | as aarch64, with `open` for `openat` and `stat` for `newfstatat` | identical to aarch64 |
| **api** (22 + 9) | as aarch64, with `open` for `openat` | identical to aarch64 |
| **vcpu** (17 + 7) | as aarch64, with `open` for `openat` | identical to aarch64 |

The programs themselves are not identical — 182/105/106 instructions against
179/103/103 — because the `ioctl` request numbers a filter names are KVM's, and
KVM's are architecture-specific: x86_64 permits the register-save requests
(`KVM_GET_SREGS`, `KVM_GET_MSRS`, `KVM_GET_XSAVE` and the rest) where aarch64
permits `KVM_GET_ONE_REG` and `KVM_GET_REG_LIST`. That is inside the conditions,
which is why the syscall lists agree while the fingerprints do not.

**One thread more than you would expect.** On x86_64 the VMM process has five
tasks, not four: `firecracker`, `fc_api`, `fc_vcpu 0`, `fc_vcpu 1`, and
`kvm-nx-lpage-re` — a worker KVM creates for its NX-huge-page mitigation, which
exists on x86_64 and not on aarch64. It reports `SECCOMP_MODE_FILTER` like the
rest, and the check requires it to. That is the strong reading and it holds on
both architectures today; if a kernel ever creates that task unfiltered, KelyfOS
will refuse the run and the refusal will name it, which is the failure that is
possible to diagnose.

## 4. What this layer does not do

It is a wall around the VMM process, and nothing else.

- **It is not the boundary.** The VM is. The filter is one of the things that
  makes an escape from the VM less useful, alongside the jailer's chroot and
  dropped uid; it is depth behind the boundary, not the boundary.
- **It does not touch the guest.** An agent inside a sandbox is still root in
  its own machine and still reaches whatever the guest kernel offers root.
  That is `docs/hardening.md` §4 and the task P5-3, and this filter neither
  helps nor hinders it.
- **It is not KelyfOS's filter to tighten.** A hand-written syscall allowlist
  for somebody else's binary is a way to produce a crash that looks like a
  security feature. If a narrower one is ever warranted it starts from
  Firecracker's published program, and the reason will be written down before
  the code is.
- **It says nothing about what the allowed syscalls can do.** `ioctl` with the
  KVM requests on this list is the whole of running a virtual machine.

## 5. Checking it yourself

```sh
bash dev/accept-seccomp.sh          # the whole claim, fifteen checks
```

Or, against a machine you already have running:

```sh
go build -o bin/seccomp-probe ./dev/seccomp-probe
sudo ./bin/seccomp-probe -pid "$(pgrep -n firecracker)"            # readable
sudo ./bin/seccomp-probe -pid "$(pgrep -n firecracker)" -format json
```

`PTRACE_SECCOMP_GET_FILTER` needs `CAP_SYS_ADMIN`, a kernel built with
`CONFIG_CHECKPOINT_RESTORE`, and a tracer that is not itself under seccomp — so
the probe wants `sudo` and is deliberately not part of the `kelyfos` CLI. It
stops each thread for the microseconds it takes to copy the program out, and
detaches on every path including the failing ones.

## 6. When this page changes

When the Firecracker pin moves. A new release means a new program, a new
fingerprint and possibly a new list, and `dev/accept-seccomp.sh` will fail with
the diff rather than let the change through quietly. Re-record with `-format
record`, read the diff, and say in the progress log what moved and why it is
acceptable.
