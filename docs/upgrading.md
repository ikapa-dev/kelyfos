# Upgrading

**Status:** reference. What breaks between versions, and what to do about it.

This page covers the breaks this project has actually shipped and can name from
the code that implements them. It is deliberately not an archaeology of eleven
tags: v0.0 through v0.8 shipped no documented breaking change, and inventing a
list of ones that might have happened would make this page less trustworthy
rather than more.

From v1.0, [`docs/compatibility.md`](compatibility.md) says what a release is
allowed to break and how much warning it must give. Everything below predates
that promise.

---

## 1. The one that matters: a snapshot taken before v0.9

**A snapshot restores the guest it captured.** Restoring one does not upgrade the
operating system inside it, and no amount of host-side work can confine a
supervisor that has no such code in it. So a snapshot taken before v0.9 comes
back as a machine whose guest confines nothing it spawns — the Landlock domains
and the seccomp refusal list that v0.9 added are inside the guest, and that guest
is the one from before.

**It is warned about, not refused.** The host walls are properties of the run you
are starting now, and all of them still apply: the jailer, the VMM's own syscall
filter, the egress policy, and the cgroup where the policy set a quota. Refusing
the restore would make every old snapshot unusable to buy nothing.

What you see:

```
this snapshot predates guest confinement, so the machine restored from it
confines nothing it spawns.
    The host walls are unchanged — the jailer, the VMM's own syscall filter, the
    egress policy still apply, and the cgroup where the policy set a quota. To
    gain the guest profile as well, re-create the snapshot under this version:
    boot a fresh machine, prepare it, and `kelyfos snapshot save` over the old
    name.
```

**The fix is to re-create the snapshot**, which means booting a fresh machine
under the current version, preparing it the way the old one was prepared, and
saving over the old name. There is no in-place upgrade and there cannot be one:
the thing that needs replacing is the guest's own userland.

**The absence is recorded, not only printed.** `session.ready` carries the guest
profile, so a run against an unconfined guest is a fact in the flight recorder
rather than a warning somebody scrolled past. A reader of the record can tell an
unconfined run from a confined one without having been at the terminal.

### The same absence, from a different cause

A guest **image** older than the CLI booting it produces the same unconfined
machine, and says so differently because the fix is different:

```
this guest image predates guest confinement, so nothing this machine spawns
is confined.
    ... update the image: `bash dev/fetch-image.sh`, or `make image` to build one.
```

And a **current** guest whose kernel cannot give it a profile is a third case,
and the least dangerous of the three: its supervisor comes up without a profile
and refuses every spawn, so it is a machine that runs nothing rather than one
that runs things unconfined. That one names the kernel options it needs —
`CONFIG_SECURITY_LANDLOCK=y`, and `landlock` in `CONFIG_LSM`.

---

## 2. Writes outside `/work`, `/tmp`, `/run` and `$HOME` are refused

Since v0.9. They succeeded before.

This project's own cookbook had a recipe that did exactly this — `mkdir
/prepared` at the root of the filesystem — and it now prepares in `/tmp`. If an
agent's setup script writes somewhere outside those four trees, that write is
where it will fail.

**There is no flag to permit it**, and the reason is structural rather than
policy: a Landlock rule covers a tree, so a rule permitting `/` grants everything
under it, including `/etc` and the toolbox the agent was handed. The narrower
grant that would be needed does not exist in the mechanism.

The writable set also includes `/dev/pts`, `/dev/shm` and seven named device
nodes. [`docs/reference/profiles.md`](reference/profiles.md) is generated from
the code that enforces it and is the current list.

---

## 3. Attaching a debugger to a process already running inside a guest

Since v0.9, `ptrace` against a process that is already running fails with
`Operation not permitted` — on **every** flavor, including `dev`, whose profile
deliberately leaves `ptrace` out of its seccomp refusal list.

The refusal is Landlock's rather than seccomp's: each confined process gets its
own Landlock domain, and Landlock refuses `ptrace` between siblings. Taking
`ptrace` out of the seccomp list does not reach it.

**Launching a program *under* a debugger still works**, because a child inherits
its parent's domain. So `gdb ./prog` is fine and `gdb -p 1234` is not, which is
the shape of the workaround: start the thing you want to debug under the debugger
rather than attaching to it afterwards.

---

## 4. Records written before v1.0

Nothing to do, and this is the point of saying it.

v1.0 changed how a record is **verified** — from the bytes as written rather than
by re-marshalling the parsed event — so a reader now tolerates a field it has
never heard of, and every chain KelyfOS has ever written still verifies. The
field order of the record is frozen from v1.0 and pinned by a test, because
reordering it would change every digest ever written and report every existing
chain as modified.

Two things did change in what a record *contains*, and neither breaks a reader
that follows the rule `docs/events.md` §3 has always stated — ignore what you do
not recognise:

- **New event types** arrive in minor releases. v1.0 alone added
  `secret.withheld`, `secret.scrubbed` and a `delete` kind on `team.store`.
- **Sessions recorded before v0.9 have no egress events at all**, because the
  proxy did not record them. A record with none is not evidence that a sandbox
  made no requests; it is evidence that this version did not write them down.

---

## 5. A sandbox started by one version, read by another

**A running sandbox is readable only by the version that started it.** The host's
own record of a machine — `sandbox.json`, and the marker a pause leaves — used to
live in the sandbox's run directory. That directory *is* the chroot the jailer
builds for Firecracker, at a uid the VMM drops to, so the one file every later
`kelyfos` process reads before doing anything was a file a compromised VMM could
rewrite. Both files moved one level up, to `<cache>/run/firecracker/<id>/`, where
a chrooted process cannot reach them at all.

The consequence is a two-way break for the length of an upgrade, and there is no
compatible middle: a fallback that still read the copy inside the chroot would be
the hole itself.

- A **new** `kelyfos exec`, `pause`, `snapshot save` or `shell` cannot see a
  sandbox an **older** one started. It reports no running sandbox rather than
  doing something wrong.
- An **older** one cannot see a sandbox a **newer** one started, the same way.
- While both are installed, `kelyfos sessions prune` and `sessions erase` lose
  the id→session mapping for machines started by the *other* version. Their other
  guards still hold — a live run directory, a paused session, a `serve-mcp`
  marker — so the risk is a chain being pruned while a team member from the other
  version is still writing into it.

**What to do:** stop the sandboxes you have running before upgrading, or leave
them alone until they finish. Nothing on disk needs migrating; a machine that has
stopped leaves nothing behind. If you run both versions side by side, do not run
`sessions prune` or `sessions erase` until only one is left.

The record is also **checked** when it is read now, whichever version wrote it:
every path and every address in it has to be one this host could have derived.
A file that fails those checks is refused with a message naming the field rather
than obeyed.

---

## 6. The workspace write-back can now refuse, and says so

Since v1.0 the whole ext4 image is refused if any entry is a socket, fifo or
device node, an absolute or climbing symlink, or a name containing a separator,
a NUL, a control character, `.` or `..`. That was documented as a security
improvement and not as a break; it is both, and these joined it:

- a **symlink chain** that leaves the workspace once every link on the way is
  followed, even where each link alone looks like it stays. A relative link that
  climbs and lands back inside — `node_modules/x -> ../../packages/x`, which is
  what every pnpm and npm workspace looks like — is still fine.
- a **file that came out of the image short** of the size its own inode records,
  which is what a failed `debugfs dump` leaves behind.
- a **directory the image would not list**, which is how a name like `notes ` or
  `my notes` used to come back created and empty.

**A refusal changes nothing.** The host directory is left exactly as it is, and
on the resume path the workspace image is **kept** rather than cleared up — it is
the only copy of what the sandbox did, and the refusal names its path so you can
go and read it with `debugfs` yourself. Nothing is written back and nothing is
removed. Previously the third case above was not a refusal at all: the workspace
came back missing a subtree, or holding a truncated file, and said `workspace
written back`.

---

## 7. `run/team.json` is gone, and a team is no longer one per host (v1.1)

Every team used to write `~/.cache/kelyfos/run/team.json`, and
[`docs/integrating.md`](integrating.md) told you to read it to map an agent's
name to its sandbox id. **That path no longer exists.** Each team now writes
`~/.cache/kelyfos/run/teams/<session>.json`, because a single file made a team a
slot: `kelyfos team up` refused to start when the file was there, unreliably,
and two teams that both got past the check overwrote each other's state (P7-16,
D79).

**The fix is `kelyfos team ps --json`**, which has been in this same release
since P7-10 and returns the roster in the shape the `team_ps` MCP tool already
guaranteed:

```sh
kelyfos team ps --json |
  python3 -c 'import json,sys
a = json.load(sys.stdin)["agents"]
print([x["sandbox"] for x in a if x["agent"] == "master"][0])'
```

Note the field is `agent`, not `name`, which is what `team_ps` has always called
it. The new directory is internal layout and is not something to read instead:
[`docs/compatibility.md`](compatibility.md) §2 does not pin it, and this is the
second time it has moved.

**Three other things move with it, and only one may need anything from you.**

`kelyfos team up` no longer refuses when another team is running — it boots.

A capped team's cgroup parent is renamed, on **both** paths: the systemd slice
from `kelyfos-team-<name>.slice` to `kelyfos-team-<name>_<session>.slice`, and
the direct one (under `KELYFOS_CGROUP_ROOT`, or as root) from
`<root>/kelyfos-team-<name>` to `<root>/kelyfos-team-<name>_<session>`. Two
teams of one name stop sharing a cgroup, which is the point. If you had a
`systemctl --user` unit file, a drop-in, or a monitoring rule matching the old
name, match `kelyfos-team-*` instead. `kelyfos team ps` prints the resolved
path, so nothing needs to reconstruct it.

`kelyfos team up` prints one more line — `session <id>`, after `team up in N
ms` — because with two teams up the name may not be unique and that is what
`--team` wants. It is on its own line and nothing else moved, so a script
grepping for `team up in` is unaffected; one comparing the whole of stdout is
not.

**What you may now have to type.** With more than one team running, `kelyfos
team ps` and `kelyfos team down` refuse to guess and list what is up; add
`--team <name|session>`. With one team running — the ordinary case — nothing
changes and no flag is needed. A script that raises exactly one team and tears
it down needs no edit; a script that raises one and reads `team.json` needs the
one above.

---

## 8. Shutdown waits for the workspace flush, and can refuse (v1.2.0)

The guest used to answer the shutdown handshake and flush afterwards, inside
`halt`. The ack therefore meant "I heard you", while the ext4 commit was still
in flight — and a teardown that won that race read the image before the last
writes reached it. The files an agent wrote in its final seconds were gone, and
both sides said `workspace written back`. That is the independent audit's IA-H1
(D91), reproduced 2/2 before the fix and 0/2 after.

The supervisor now runs `syncfs(2)` against `/work` **before** it answers, so
the ack means the files are on the disk. Three things follow that you can
observe:

- **A shutdown can take longer.** It waits for the flush, which is what the
  grace period was always for. The host's read deadline on the handshake is now
  that grace rather than a fixed two seconds — a short fixed deadline would kill
  the VMM mid-`syncfs` on a slow disk and reintroduce the very race through the
  fix.
- **A failed flush refuses the shutdown**, with the error, rather than
  proceeding and hiding it. Previously there was nothing to fail.
- **An empty write-back against a non-empty pack is refused.** The write-back
  cross-checks the pack manifest: zero extracted entries where the pack held
  files is the shape data loss takes, so it refuses, leaves the host directory
  untouched, and says why — the same behaviour §6 describes for a hostile entry.

**The trade, stated plainly:** a run whose agent genuinely deleted every file in
the workspace is now refused with that message instead of silently writing back
an empty tree. That is the intended direction — this product does not print
success on a doubt path — but if you have automation that expects an emptied
workspace to be written back, it needs `--no-sync-back` or a file left in place.

Nothing changes on the clean path. A normal run flushes a quiet filesystem in
milliseconds and shuts down as it always did.

---

## 9. An old guest image can no longer boot against a new CLI (2026-09-01)

**The guest-initiated vsock channels now take a per-session credential**
(`docs/protocol.md` §1.7; the independent audit's A2/A3, D99). The host
refuses — and records — any connection to ports 10100, 10101 and 10102 whose
first frame does not carry it, which includes the ready frame: a supervisor
that predates the handshake cannot present what it was never given, so the
machine never becomes ready and the boot fails.

A supervisor old enough to predate the handshake says so itself: the host's
`auth` op is answered `bad_request`, and the boot ends with the refusal
instead of a timeout:

```
this image's supervisor does not accept a channel credential — it predates
the authentication handshake the running CLI requires.
    rebuild the guest image for this CLI:  make image FLAVOR=dev   (or FLAVOR=base)
```

**What to do:** rebuild the image — `make image FLAVOR=dev`, or `base` for
the flavor a team's spawn budget names. The CLI and the image were always one
system where it matters; this change makes the coupling explicit where before
it was silent.

**Snapshots are the harder edge, said plainly.** A snapshot's frozen memory
*is* its supervisor, so a snapshot taken before the handshake can never learn
a credential — restoring one under this CLI is refused with the same named
error, and rebuilding the image does not fix it. The way forward is to re-take
the snapshot: boot a fresh machine on the rebuilt image, prepare it, and
`kelyfos snapshot save` over the old name. That is the same answer §1 gives
for pre-v0.9 confinement, and for the same reason: restoring does not upgrade
the guest inside it.

**Why a refusal rather than a warning:** the ready, events and team channels
are how the record learns what happened inside the machine. A machine whose
guest cannot authenticate those channels is a machine whose record can be
forged by any process inside it, and starting one that looks ordinary would
repeat the exact gap the credential exists to close. The precedent is P5-3's
profile refusal — a machine that confines nothing is refused, not warned
about — and D99 records the reasoning.

---

## 10. What has never broken

Stated because "nothing changed" is only useful if somebody checked:

- `proto.Version` has been `1` for every release, and `recorder.Version` has been
  `1` for every release. The wire protocol and the record format have not changed
  incompatibly since they existed.
- `kelyfos.toml` has only ever gained keys. Two spellings kept "for
  compatibility" since v0.4 are still accepted, and
  [`docs/compatibility.md`](compatibility.md) §4 is where their removal now has to
  be announced rather than simply happening.
