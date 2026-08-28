# Hardening — the shapes, before the code

*Specification for v0.9, written before Phase 5 builds it. The parts that need a
shape agreed in advance are here; the parts that are mechanism with nothing to
decide are not.*

*Where this document and the code disagree during the phase, the code is wrong
and this page is the thing to argue with. After the phase, the reverse — and two
exit exams in a row have found places where that reversal had not been made, so
it is worth saying a third time.*

---

## The sentence this exists to replace

Every KelyfOS release so far has carried this, in the README, directly under the
benchmark numbers:

> **Not hardened yet** — read [`docs/threat-model.md`](threat-model.md) before
> trusting it with anything.

It has been true. KelyfOS relies on the boundary Firecracker gives it — a real
VM, a real hardware boundary — and adds nothing of its own around the VMM
process on the host or around what a compromised agent may reach inside its own
guest. That is a defensible place to have been while the product was being built.
It is not a defensible place to stay, and the phrase is doing real work for
somebody deciding whether to run this.

**Phase 5 is finished when that sentence can be replaced by one that is also
true**, and the replacement must say what *is* enforced and what is *not*. A
sentence that says "hardened" and stops would be a worse lie than the one it
replaced.

*Replaced at P5-4.* The README now carries a two-part statement in both places
the old sentence appeared — a table of what is enforced, and a list of what is
not, the second longer than the first. The word "hardened" does not appear in
either as a claim about the product. What replaced it can be checked against §5
below, which was written before any of it was built for exactly that purpose.

---

## 1. What a compromised agent can reach today

The honest inventory, because everything below is measured against it.

### 1.1 Inside its own guest: everything

The agent runs as root in the guest. There is no user separation inside a
KelyfOS sandbox and there never has been: the supervisor is PID 1, `kelyfos exec`
runs commands as root, and a plugin is a process the supervisor spawns. An agent
that runs `rm -rf /` has done nothing it was not permitted to do.

What limits it inside:

| | |
| --- | --- |
| the root filesystem | read-only, with a tmpfs overlay — and since P5-3 a write outside the profile's writable trees is refused with `EACCES` rather than landing in the overlay |
| `/work` | the only durable thing, and only when a workspace was attached |
| the network | the proxy or nothing; no NIC at all without `--allow` |
| memory, cores, disk | the caps in `[resources]`, enforced host-side (E1) |

What does **not** limit it: the syscall surface of the guest kernel, which is
whatever the kernel offers to root. A kernel bug reachable from inside is
reachable from inside.

### 1.2 The host: the VM boundary, and nothing else

No path from guest to host exists except the vsock channels the supervisor
serves and the egress proxy, both of which are the host's own code deciding what
to do. That is the design and it holds.

What is *not* defended is the case where the boundary itself fails. Today the
Firecracker process runs:

- **as the invoking user** — so a VMM escape gets that user's filesystem,
  their SSH keys, their `~/.cache/kelyfos` with every session record in it;
- **in the invoking user's mount namespace** — the whole host filesystem is
  addressable;
- **with the KelyfOS cgroup applied** (E1), which is a resource limit and not a
  security boundary.

Firecracker's own seccomp filter is on by default in a release binary, which is
a real protection this project got for free and did not check until P5-2. It is
checked now, on every run and every restore, and a VMM with an unfiltered thread
is refused rather than reported (§3).

---

## 2. Layer one: the jailer

Firecracker ships `jailer`, and KelyfOS already installs it —
`dev/install-firecracker.sh` puts it beside the VMM and prints its version. It
was unused until P5-1; every sandbox goes through it now unless `--no-jail` is
passed, and `requireJail` refuses to build one on a machine that cannot run
`sudo -n jailer`, before anything is created.

### 2.1 What it does, precisely

Verified against the jailer documentation for v1.16.1, the version pinned in
`versions.mk`:

| | |
| --- | --- |
| `--chroot-base-dir` | builds `<base>/<exec-file-name>/<id>/root` and `pivot_root()`s into it |
| `--uid` / `--gid` | drops to them after the namespaces are set up — to the invoking user, which under sudo is the drop that keeps the jail from being a regression (D29) |
| `--parent-cgroup` | places the process inside an existing cgroup — which is how it composes with the caps KelyfOS already sets |
| `--netns` | joins a network namespace, if one is given |
| `--resource-limit` | `fsize` and `no-file` bounds |
| `--new-pid-ns` | its own PID namespace — deliberately not passed: it makes the jailer fork and the parent return, so the process KelyfOS waits on would exit the moment the machine started |

Inside the jail it `mknod`s `/dev/kvm` and `/dev/net/tun` and chowns them to the
target uid. KelyfOS passes its own `--api-sock`, so the API socket is
`<chroot>/fc.sock`, and the host keeps its own absolute path to the same file in
`State.APIPath`.

### 2.2 The part that is work rather than a flag

> "The user must create hard links for (or copy) any resources which will be
> provided to the VM via the API (disk images, kernel images, named pipes, etc)
> inside the jailed root folder."

That sentence is most of P5-1. Every file a KelyfOS microVM touches has to be
inside the jail: the kernel image, the rootfs, the workspace device, the plugins
device, the snapshot state and memory files, and the vsock Unix socket that
every host-side channel dials. The host keeps its own path to that socket —
`kelyfos exec` and every other command find the sandbox through
`State.UDSPath` — so the state file records where it now lives.

**And one thing must stay outside**: the flight recorder. A record the jailed
process can reach is not a record. It already lives outside the run directory
because the record must outlive the machine (P2-4); now it must also live
outside the jail, for a second and stronger reason.

### 2.3 The decision this forces

**Every entry point goes through the jailer, or none does.** `run`, `team up`,
`fork`, `snapshot restore`, `serve-mcp` and `shim` all start microVMs. A
hardening that half of them skip is a hardening nobody can reason about, and the
half that skips it will be the half somebody uses.

---

## 3. Layer two: the host syscall filter

Firecracker's seccomp filters are **on by default** in a release binary.
`--no-seccomp` turns them off and its own documentation says not to use it in
production; `--seccomp-filter <file>` replaces them with a filter compiled by
`seccompiler-bin`, and the documentation warns that a misconfigured one can
"disable the seccomp security boundary altogether".

So the work here is not to write a filter. It is to **prove the default one is
in force** — read from `/proc/<pid>/status`, on the host, in the acceptance,
rather than assumed from the fact that nobody passed `--no-seccomp`. A
protection you have never observed is a protection you are hoping for.

A hand-written syscall allowlist for somebody else's binary is a way to produce
a crash that looks like a security feature. If a custom filter is ever
warranted, it starts from Firecracker's published one.

*Written after P5-2, because the task went further than this section asked.*
The mode is read on **every thread** of the VMM, not on the process, because
Firecracker installs its filters without `TSYNC` and one unfiltered thread is a
hole a process-level read cannot see — and a VMM without a filter is refused
with `[seccomp.not_in_force]` rather than merely reported. The permitted set is
recorded in [`host-seccomp.md`](host-seccomp.md), read out of the running kernel
with `PTRACE_SECCOMP_GET_FILTER` and interpreted, rather than transcribed from
the JSON; the two agree exactly, which is the point of having done it twice.

---

## 4. Layer three: what the supervisor grants what it spawns

The guest side, and the one with real design in it.

### 4.1 Two mechanisms, and what the kernel actually has

**seccomp is available today.** The guest kernel is built with
`CONFIG_SECCOMP=y` and `CONFIG_SECCOMP_FILTER=y`; nothing needs rebuilding to
filter syscalls for the processes the supervisor spawns.

**Landlock is not.** The guest kernel is 6.12.105, whose Landlock ABI is **6**
— the newest there is, and the same ABI `golang.org/x/sys/unix` exposes, so the
kernel version this project moved to at D28 costs nothing here. But
`CONFIG_SECURITY_LANDLOCK is not set` in the built config, and `CONFIG_LSM` does
not list `landlock`. **Both** are needed: compiling the LSM in without naming it
in `CONFIG_LSM` leaves it inactive, which is exactly the kind of half-measure
that reads as protection in a config file and is none at runtime. P5-3 includes
a kernel config change and a rebuild.

*Written after P5-3: this is done.* `image/buildroot/kernel/kelyfos.fragment`
now sets `CONFIG_SECURITY_LANDLOCK=y` and names `landlock` first in
`CONFIG_LSM`, and the guest reports ABI 6 —
`/sys/kernel/security/lsm` reads `capability,landlock`. The paragraph above is
kept as written because it is the reasoning the change was made from, and
because "both are needed" is the part a future kernel bump can quietly undo.

### 4.2 What a profile may not break

A profile that breaks the toolbox has hardened nothing. Three things must keep
working, and the acceptance checks them rather than trusting them:

- `/work` stays writable, because that is the whole point of a workspace;
- the read-only root stays readable, because that is where the programs are;
- the supervisor's own vsock channels stay reachable, because that is the
  entire interface. (They are: Landlock at ABI 6 governs the filesystem and TCP
  bind/connect, and `AF_VSOCK` is outside both — verified in the kernel's own
  `security/landlock/net.c`, which returns early for any address family that is
  not `AF_INET`/`AF_INET6`.)

*Written after P5-3: this is a visible change, and it broke something.* Writing
anywhere outside those trees now fails with `EACCES`, and that includes creating
a new directory at the root — `mkdir /prepared`, which one of the cookbook
recipes did. There is no way to permit that and still refuse `/etc`: a Landlock
rule covers a tree, so granting the root grants everything under it. The recipe
now prepares in `/tmp`, which is where it belonged, and the v0.9 release notes
say plainly that a command writing outside `/work`, `/tmp`, `/run` and `$HOME`
is refused from v0.9 where it succeeded before. Those four trees are not the
whole writable set: `/dev/pts` and `/dev/shm` get the same write rights —
`/dev/shm` is a general-purpose tmpfs and not a device node — and seven device
nodes (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`,
`/dev/tty`, `/dev/ptmx`) may be read, written and truncated, because a profile
that granted only the four broke `git`, which opens `/dev/null` read-write
before it does anything else. The release notes live only in the GitHub release
body: this repository has no `CHANGELOG.md` yet, so nothing in the tree carries
that statement and nothing keeps the two in step. P6-16.

*Written after F10, the security review of 2026-08-28: what "writable" grants
no longer includes making a device node.* It did, on every tree in that list,
and a confined process is root — so `awk '/vdb$/ {print $1, $2}' /proc/partitions`
followed by `mknod /root/disk b 254 16` produced a working block device for the
workspace disk, and `dd` read it raw. That is past the `nosuid,nodev` mount that
guards `/work`, past `/dev` never being granted wholesale, and past the sentence
in `profile.go` saying the raw disks are not on the list. Reproduced on a booted
guest before it was fixed, because as a non-root user the `CAP_MKNOD` check
answers `EPERM` first and hides whatever Landlock would have said.

Two layers now, because one of them is a grant and grants get widened:

- **`MAKE_CHAR` and `MAKE_BLOCK` are no longer granted.** They are still
  *handled* by the ruleset, which is the whole of the difference: a right the
  ruleset does not name is not restricted but ignored, so removing them from
  what is governed rather than from what is granted would have permitted device
  nodes everywhere, `/etc` and `/usr` included. `MAKE_FIFO` and `MAKE_SOCK`
  stay — `mkfifo(3)` and a unix socket are things real programs create, and both
  are checked in the acceptance run.
- **The merged root is mounted `MS_NODEV|MS_NOSUID`.** It was mounted with no
  flags at all. A mount's flags are its own: the lower layer is the read-only
  image and the upper is a tmpfs already carrying both, and neither lends
  anything to the merged mount on top. The image ships no device node outside
  `/dev`, and `/dev` is a devtmpfs moved across afterwards with its own flags,
  so `nodev` costs the guest nothing; `nosuid` retires the setuid bit on
  `/bin/busybox`, which buys nothing today because every process here is already
  root, and is therefore exactly the moment to drop it.

**`mknod` and `mknodat` are deliberately not on the seccomp refusal list**, and
a test pins them off it. `mkfifo(3)` *is* `mknodat` with `S_IFIFO`, and this
filter compares syscall numbers with no sight of the mode argument, so refusing
the number would refuse every named pipe in the guest — a far larger break than
the hole it closes. Landlock and `nodev` both see the file type; the number-only
filter cannot.

### 4.3 Per flavor, and refusing rather than degrading

The profile is declared per image flavor, because `base` and `dev` are different
machines with different jobs. And when the kernel cannot apply it — an ABI that
is too old, an LSM that is not compiled in — nothing continues with the profile
silently absent. *Written after P5-3, because the shape is not the one this
sentence first predicted:* the supervisor comes up and reports the absence in
its ready frame; the **host** refuses a cold boot with `[profile.not_enforced]`;
every process the supervisor would spawn is refused by the confining step
itself; and a restore is warned about rather than refused, because the host
walls are unchanged and refusing would make old snapshots unusable to buy
nothing (D32).

That is the same rule the rest of this product follows and for the same reason:
a limit that is quietly not applied is worse than no limit, because somebody is
relying on it.

### 4.4 Written after P5-3: how it is applied, and one thing it also does

Both mechanisms restrict the *calling thread* and are inherited across fork and
exec, and Go offers no safe hook between the two — after `fork` only
async-signal-safe work is legal, which rules out the Go runtime. So the
supervisor re-execs itself: the command becomes `/proc/self/exe --confine
<flavor> --path <resolved> -- <argv…>`, and that process applies the profile to
itself and then `execve`s the real program. Nothing of the runtime has to
survive the restrictions, because they go on immediately before the exec that
replaces the process. The original `argv` is carried through untouched, which
matters more than it sounds: BusyBox is one binary that decides what to be from
`argv[0]`.

It is applied in `reaper.startAndRegister`, the single place every child is
started, for the reason `requireJail` lives in `sandbox.New` — a confinement
three call sites have to remember is one that a fourth will not.

*Written after F8, the security review of 2026-08-28: "every child" was the
design and not the behaviour.* `confine` carried a re-entrancy guard that asked
whether the target's path ended in `kelyfos-confine` — the `argv[0]` the wrapper
runs under, but a property of the program being started rather than of the
wrapper. It never once fired for the case it was written for, because a command
already rewritten has the path `/proc/self/exe`, which does not end in the
marker. It fired for one case nobody wanted: a program the agent had named after
the helper. A file placed at `/root/kelyfos-confine` — `/root` is writable and
executable under both flavors — and then `exec`'d by that path produced a child
of PID 1 with no Landlock domain and no seccomp filter, which is every syscall
on the refusal list and every tree the profile withholds. The review that found
this wrote the step as `cp /bin/sh /root/kelyfos-confine`, which does not work
on this image: `/bin/sh` is a symlink to BusyBox, and BusyBox decides what to be
from `argv[0]`, so a copy of it under that name answers `applet not found` and
exits 127. A shebang script under the same name does work, and needs nothing
installed — the kernel runs `/bin/sh` for it, unconfined, because the process
that was never confined is the one that `exec`'d it.

Two changes close it, and the second is the one that matters. The guard is now
keyed on the wrapper's own identity — `cmd.Path == "/proc/self/exe"` **and**
`cmd.Args[0] == "kelyfos-confine"` — which is not a pair an agent can produce.
`Args[0]` is the string the caller passed; `Path` is what `exec.Command` made of
it. The two do diverge — a bare name is resolved against `PATH` — but never into
that pair. A name containing a separator is taken verbatim, so a `Path` of
`/proc/self/exe` means `Args[0]` is `/proc/self/exe` too, which is not the
marker. A bare name is resolved by `LookPath`, which joins a `PATH` directory to
that same name, so a `Path` of `/proc/self/exe` would require the name `exe` —
and then `Args[0]` is `exe`, which is not the marker either. There is no argv
that produces both halves. And `startAndRegister` no longer
believes `confine`: it asserts the invariant afterwards and returns
`errNotConfined` instead of starting anything that fails it. The first makes this
hole closed; the second makes the *class* of it closed, because the next early
return somebody adds to `confine` now stops a process rather than releasing one.
The supervisor already refuses to report ready on a profile it could not
enforce; this is the same refusal one step earlier.

Two things it deliberately does not refuse. A command that was never found is
still reported as not found rather than as a confinement failure — the assertion
reads `cmd.Err` first. And a supervisor holding no profile at all still spawns,
which is the pre-v0.9 image and the pre-v0.9 snapshot of D32 rather than a
current guest on a Landlock-less kernel: that one resolves a profile object, the
host refuses its cold boot, and the confining step refuses every spawn with exit
126. §4.3 above and [`upgrading.md`](upgrading.md) §1 keep the three apart.
`supervisor/confine_test.go` is the proof by unit test;
`dev/accept-profile.sh` puts that program at `/root/kelyfos-confine` in a real
microVM, runs it, and reads the answer out of the child's own
`/proc/self/status`.

**And a consequence worth stating, because it is a protection nobody asked
for.** Each confined process gets its own Landlock domain, and Landlock's
`ptrace` hook refuses introspection *between sibling domains*. So two commands
in the same sandbox cannot read each other's `/proc/<pid>/exe`, or attach to one
another, even though both run as root and even on `dev`, where the profile
leaves `ptrace` out of the refusal list. A debugger that *launches* its target
still works — the child inherits its parent's domain — which is the case that
matters. Attaching to an unrelated process does not. This was found by an
acceptance test that killed a plugin by scanning `/proc/*/exe` and stopped being
able to see it; the test now matches on `cmdline`, which needs no such access.
Signals themselves are not scoped, so `kill` between siblings still works.

---

## 5. What remains reachable afterwards — the longer half

Stated here, before the code, so the README sentence at the end of the phase can
be checked against it rather than composed to sound good.

**The invoking user's own processes.** The jailed VMM drops to the user who
started it rather than to a dedicated account (D29). The chroot takes the host
filesystem away entirely — verified from the host's own `mountinfo`, not claimed
— but a uid shared with your shell is a uid that can signal and `ptrace` your
other processes. A dedicated service account closes that and costs a second
setup step; the trade is priced in D29 and is revisitable. The host's process
list is still visible too, because KelyfOS does not pass `--new-pid-ns`: it
makes the jailer fork and the parent return, and supervising the VMM is worth
more than hiding a process list from a VMM that is already chrooted and
unprivileged. It is not the only jailer flag left unpassed — `--netns` and
`--resource-limit` are not used either, and §2.1's table lists what is.

**The guest kernel.** An agent is still root inside its own guest and can still
reach the whole syscall surface the seccomp profile permits. Landlock restricts
the filesystem; it does not make the kernel smaller. *After P5-3:* the profile is
a refusal list, not an allowlist, so the surface it leaves is everything a
kernel offers root minus the names on that list — twenty-eight of them, of which
`dev`, the flavor a release publishes, takes `ptrace` back out, and aarch64
drops `settimeofday` because it has no such syscall to refuse. A real reduction
at exactly the places that matter (no module loading, no mount, no clock, no
keyrings) and not a small surface. Landlock also cannot restrict `chdir`,
`stat`, `chmod`, `chown`, `access` or `fcntl` at all, by its own documentation,
and cannot restrict a file descriptor that was already open when the profile was
applied — so what the supervisor hands a child on its stdin and stdout is
outside this layer by construction. `LANDLOCK_ACCESS_FS_IOCTL_DEV` is left out
of the rights the ruleset handles, which is this project's choice rather than a
Landlock limitation: handling it without granting it on `/dev` would refuse the
terminal ioctls every interactive program makes, so ioctls on device nodes are
not governed at all.

**The supervisor itself.** Both mechanisms are applied by the re-exec'd
`--confine` helper and nowhere else, so PID 1 is not confined by the profile it
applies to everything it spawns, and a tool running inside the supervisor has
the whole filesystem in front of it. `write_file` is bounded to the
same three lists the profile is built from instead (`writableFor`, P6-24), so
the file tools get the reach a confined child gets and no more. *Since F11 of
the 2026-08-28 review that bound is enforced at the open rather than checked
before it:* the tool used to walk the path with `Lstat`, twice, and then hand the
absolute path to `os.MkdirAll` and `os.WriteFile`, which resolve it again — and
the second walk's own comment named the gap between the two without closing it.
A confined exec holds `MAKE_SYM` on every tree it can write, so a loop planting
and removing a link at the target raced that gap; the walk returns at the first
component that does not exist, which for a file being created is immediately, so
the window was the whole of `MkdirAll`. The write now goes through an `os.Root`
anchored on the matched tree — `openat2` with `RESOLVE_BENEATH` — which refuses a
path that leaves the tree at the moment it opens it, with nothing to race. The
`Lstat` walk stays in front for its error message and for the in-tree symlink
this project already refused, which `RESOLVE_BENEATH` alone would follow. Reads are
deliberately not restricted at all: the profile grants read beneath `/` to those
children anyway, so restricting the tool would make it weaker than the thing it
serves while closing nothing.

**The other agents' machines, still not reachable** — that was already true and
this phase does not improve it. It is listed because a reader deciding whether
to trust a team needs to know which protections are new and which were always
there.

**The host, if Firecracker itself is escaped.** The jailer makes that far less
useful — a chroot, a dropped uid, no access to the invoking user's home — but
"far less useful" is not "impossible", and anyone who tells you a chroot is a
security boundary is selling something. The VM is the boundary; the jailer is
depth behind it.

**Anything the policy file permits.** A sandbox allowed to reach
`api.github.com` with a token bound to it can do whatever that token can do.
Hardening the sandbox does not harden the credential, and no layer in this phase
touches that.

**Side channels.** Nothing here addresses timing, cache or speculative-execution
channels between a guest and its host or between two guests on one machine.
Firecracker documents its own position on those; KelyfOS inherits it and adds
nothing.

**Reproducibility is measured rather than claimed.** Four knobs are on —
`BR2_REPRODUCIBLE`, `SOURCE_DATE_EPOCH` taken from the commit rather than the
clock, a fixed ext4 UUID and directory hash seed, and `gzip -n` — and the
`repro-check` workflow builds the same commit twice and diffs it per artifact,
because turning a knob on is not the same as the thing working. Upstream calls
Buildroot's reproducible mode experimental and requires an identical build path;
the compiler cache has been mixing cached and fresh objects in every build this
project has ever done; and until v1.0 nobody here had measured it at all.

Measured: the two Linux CLI binaries are identical when built from two
*different* source paths, and `Image`, `rootfs.ext4` and `image.json` are
identical across two full aarch64 `dev` builds from nothing on one machine with
an identical build path. That last is the scope, and the scope is part of the
answer — one machine, one architecture, two builds. It is not a claim that
anybody else's machine produces these bytes. Nor is it a claim about all four
CLI binaries: `make release-cli` also builds `kelyfos-darwin-x86_64` and
`kelyfos-darwin-aarch64`, which ship in the release, and `repro-check` used to
compare `dist/kelyfos-linux-*` only. The workflow now builds and compares
`dist/kelyfos-*` — every binary the release ships — across the two source paths,
and `TestEveryReleasedCLIBinaryIsMeasuredForReproducibility` in `tools/sbom`
fails if a released binary ever falls outside those globs again. **The two macOS
binaries are inside the check and have not been measured**: widening a check is
not a result, and no run has reported on them. Until one does, what is measured
is what this paragraph opens with: the Linux pair, and nothing either way about
the macOS pair.

**An SBOM ships with every release**, one per architecture, covering all four
places the shipped bytes come from: Buildroot's packages, the guest supervisor,
the Linux host CLI, and the macOS CLI for that same architecture. `release-sbom`
reads all three of those binaries' own build information, so every CLI the SBOM
attestation's subject glob sweeps up — `dist/*aarch64*` or `dist/*x86_64*` — is
one the SBOM opened. Before v1.0 the macOS CLI was in no SBOM while that glob
matched it anyway, so one shipped artifact per architecture was attested as
being described by an SBOM that never read it, and
`TestEverySBOMSubjectIsABinaryTheSBOMRead` in `tools/sbom` is what notices if
the glob and what the SBOM reads drift apart again. The three that are not
Buildroot's matter more than the count does. The supervisor is PID 1 and it is
cross-compiled by this project's own toolchain, arriving through the rootfs
overlay rather than as a Buildroot package — so **Buildroot
has never heard of it**, and an inventory from that source alone would omit the
one component KelyfOS actually wrote. An SBOM that is confidently incomplete is
the supply-chain form of an audit record that is confidently wrong.

The Go halves are read with `debug/buildinfo`, which survives the `-s -w` these
binaries are stripped with: those flags drop symbols and DWARF, not the build
information. So the dependency list is the linker's answer rather than
`go.mod`'s — what was built, not what was declared. The component count is
printed from the document that was produced rather than transcribed into a
release note, because a total written down by hand is a total that is right
once. It is covered by `SHA256SUMS` rather than published beside it.

**Release artifacts the workflow builds are attested — which does not yet
include a *published* one: the workflow drafts, and publishing is a person's
decision. `v1.0-rc2` is the first release it built, and it carries them.
`actions/attest` has GitHub sign a statement naming the workflow and the commit
that produced the checksums file — one attestation covering every asset — and a
second and third over each architecture's SBOM. `gh attestation verify <file> --repo p4r4n0rm4l/KelyfOS`
checks it, offline, against a root fetched once. That is SLSA v1.0 Build
Level 2, and it means what it says and no more: a hosted builder attesting to
its own output. It is **not** the immutable-release setting, which asserts that
GitHub received these bytes under this tag and carries no builder identity at
all; the two are separate things and never share a sentence.

**The supply chain, beneath the release.** Signing the *images themselves* — as
opposed to attesting the release artifacts, which the workflow does — has no task and no
date, and neither does verifying the layer under Buildroot: the compiler and the
upstream tarballs are taken on trust, checked by checksum against what upstream
published and no further. A hardened runtime built from an unverified toolchain
is still a locked door in a wall nobody measured. The door is now documented down
to its hinges; the wall is not.

---

## 6. What this phase will not do

**No user separation inside the guest.** An agent runs as root in its own
machine and will continue to. Adding a second user inside a single-purpose VM
buys a boundary weaker than the one already around it, and costs every recipe.

**No custom Firecracker seccomp filter**, per §3.

**No new policy surface.** Nothing here adds a way to widen anything: the
profiles narrow, and `kelyfos.toml` gains no key that can turn a layer off. A
hardening feature with an off switch in the project's own config file is a
hardening feature with an off switch. *Stated precisely, because there is one
off switch:* `kelyfos run --no-jail` exists, on the command line and not in the
policy file, for a machine that cannot grant the jailer passwordless sudo. It
prints what is not enforced on every run that uses it and records
`jailed: false` in the chain, so it cannot be used quietly — which is the
property that matters, not its absence.

**No claim that this makes KelyfOS suitable for hostile multi-tenancy.** It is a
single-host developer tool (D1). This phase makes a compromised agent much less
useful to an attacker; it does not turn the product into a public cloud.

---

## 7. Conformance

| Requirement | Task |
| --- | --- |
| This spec | P5-0 |
| Firecracker under the jailer, every entry point, records outside the jail | P5-1 |
| The host filter proved in force rather than assumed, and what it permits recorded in [`host-seccomp.md`](host-seccomp.md) | P5-2 |
| Per-flavor guest confinement, refusing rather than degrading; Landlock compiled in and named in `CONFIG_LSM` | P5-3 |
| Bars re-earned on the bare-KVM reference; the README sentence replaced; the threat model agreeing | P5-4 |
| Launch assets | P5-5 |
