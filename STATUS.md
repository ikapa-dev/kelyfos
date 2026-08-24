# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main

## Plans
- PLAN.html — **46/53**. Phase 5 **closed at v0.9**. What remains is Phase 4, an unordered backlog
  with no exit checkpoint: P4-3, P4-6, P4-7 unstarted; P4-4 and P4-5 [BLOCKED] on their own conditions.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.

## Now
Nothing in flight. Phase 5 closed, v0.9 tagged and published, and acceptance item 8
answered: the quickstart is re-timed against the v0.9 release and the README carries the
measured figures. What remains is Phase 4, an unordered backlog with no exit checkpoint.

**P5-5 done.** The recording is a real session from a committed script — boot, a refused
egress with its fix line, five agents, the chain verified — 202 KB, 14.3 s, with the cast
committed beside it. The README's opening screen was cut back to what a stranger needs in
ten seconds. The HN post is v0.9 reality, still posted nowhere.

**P5-4 done.** Bars re-earned on the bare-KVM reference across the change of posture:
cold boot 123 → **135 ms**, restore 37 → **49 ms** (about 12 ms each way for the jailer,
the filter check and the profile probe); both targets hold with room. Five agents:
**737 ms** cold, **149 ms** forked. Quickstart re-measured from nothing, sudoers step
included: **149 s** on macOS, 10 s of it on a Linux box. The "not hardened yet" sentence
is gone from both places it appeared. Every acceptance suite in dev/ green — 239 checks,
0 failed — plus the cookbook and the Go suite.

Both P5 deviations were endorsed by the owner (2026-08-24) and logged in D32 and D33.
The `session.ready` placement is now doctrine for any record field added later: a choice
may ride the opening event, an observation rides ready. The absent catalog entry stands;
no guest-side refusal mechanism is to be built to create one.

**P5-8 done.** The sibling-ptrace refusal is named in docs/denials.md's own
what-is-not-in-the-catalog section and in the generated profiles page, with both halves
proved by a shell: a command can introspect a child it started, and cannot introspect a
sibling. A false claim was corrected on the way — `dev` ships no debugger.

**P5-9 done.** `snapshot restore` was failing outright for any machine that had a
workspace — the captured copy was staged after the load, and since P5-1 the recorded drive
path is chroot-relative, so the load had nothing to open. Staged before the load now, by
copy rather than link so two forks cannot share the blocks. accept-jail's snapshot section
attaches a workspace now, which is why it was invisible: no suite did.

**P5-7 done.** A restore learns the guest's confinement over the control channel — on the
resync round trip it already makes — and `session.ready` carries it on all eight paths,
including team members and the shim, which `session.start` never covered. That also closes
P5-1's `jailed` gap. A pre-confinement snapshot warns and is not refused (D32).

**Protocol change, in force now:** PLAN.html §8 gains rule 8 — start-up reconciles against
the latest CI run for `origin/main`, and a red `main` is fixed before any new task.

## This session
Start-up reconciliation clean at 4c8fa5b. **P5-2 done**: which filter (a test on the argv
tail the jailer forwards verbatim), that it is on (every VMM thread read from `/proc`,
refused with `[seccomp.not_in_force]` when it is not, proved by causing the refusal), and
what it permits (`PTRACE_SECCOMP_GET_FILTER` + an abstract interpreter over the real BPF).
Both arches agree syscall for syscall with Firecracker's published JSON: 50/31/24 distinct
for vmm/api/vcpu. New: `dev/seccomp-probe`, `dev/accept-seccomp.sh` (15/15 aarch64, 14/15
+1 skip on the CI reference), `dev/expect/host-seccomp-{aarch64,x86_64}.txt`,
`docs/host-seccomp.md`. Also fixed: **`main` had been red since P5-1** — the smoke test
asserted the pre-jail run-directory layout; nothing was actually left behind, and the check
now tests the claim.

**P5-6 done** (the task D30 created out of a regression P5-2 found). Two defects, not the
one-line fix D30 guessed at: the jailed path replaced the command line instead of also
wrapping it, so no systemd scope was ever created; and `--parent-cgroup` went without
`--cgroup-version 2`, which the jailer's own default of version 1 makes a silent no-op on
a v2 host. Three acceptance scripts were also still reading the pre-jail run-directory
layout, so E1's acceptance had been measuring nothing rather than failing — it now reports
13/13 with 0.49 cores against a 0.5 ceiling. accept-jail is 17/17, closing this phase's
acceptance item 2. Also, on the owner's instruction: PLAN-FEATURES.html's E4 and E5
carried stale `data-status` attributes in a closed document; both are `done` now and all
five epics render green.

**P5-3 done.** The guest kernel gained Landlock (both halves — compiled in *and* named in
`CONFIG_LSM`; `/sys/kernel/security/lsm` now reports `capability,landlock`). Every process
the supervisor spawns is confined at `reaper.startAndRegister`: Landlock for the
filesystem, a 28-name seccomp refusal list, applied by a re-exec that restricts itself and
then execs the target (D31). accept-profile 23/23; a write to /etc, /usr, /lib refused by
the kernel and the same write in /work fine; git, python3, `mv` across trees, the pty
shell and argv[0] dispatch all intact. Full sweep green: 11 suites, the Go suite, 14
cookbook recipes.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] on their own written conditions. `idle_timeout` refused (F-D20;
  F-D22). IMAGE_DIR per-arch not per-flavor: parked.
- **P5-1 left `session.start`'s `jailed` field on `kelyfos run` only** — the other seven
  emitters omit it, so a `team up` / `fork` / `restore` transcript says nothing about the
  wall that was around it. Understatement rather than overstatement, so not urgent; routed
  to P5-4, which is where claims are reconciled with reality.
- Fragility worth knowing: on x86_64 the VMM process carries a fifth task,
  `kvm-nx-lpage-re`, created by KVM. It reports filter mode today and the check requires it
  to. A kernel that ever creates it unfiltered would produce a false refusal — which names
  the thread, so it is diagnosable.
- `CONTRIBUTING.md` requires a DCO `Signed-off-by` on every commit; commits have not
  carried one for some time. Not fixed here — rewriting history is forbidden and adding it
  now would be inconsistent with the run of commits before it. John's call.
- Release-note items. (2) and (3) below are now tasks — P5-7 and P5-8 — rather than notes;
  (1) stays a release note for P5-4. (1) A
  guest command that writes outside `/work`, `/tmp`, `/run` and `$HOME` is refused from
  v0.9 where it succeeded before — one cookbook recipe did exactly this and now prepares
  in `/tmp`. (2) A snapshot taken before v0.9 restores into the guest it captured, which
  has no profile and no jail-era supervisor; it is not upgraded by being restored.
  (3) Landlock refuses ptrace between sibling processes, so attaching a debugger to an
  already-running process fails even on `dev`; launching the target under the debugger
  works, because the child inherits the domain.
- Minor, not chased: `kelyfos runs --all` silently skips a session directory it cannot
  read (one was left root-owned by a `sudo` diagnostic in this session). It counts as
  missing rather than reporting "1 unreadable".
- Measurement debt for P5-4: cold boot-to-ready and snapshot restore re-measured on the
  bare-KVM reference with jail and filter on the boot path, and the quickstart ≤5-min
  figure re-measured *including* the sudoers step.

## Toolchain
Buildroot **2025.02.17** (LTS, EOL March 2028) · Linux **6.12.105** (longterm, EOL
December 2028) · Firecracker **v1.16.1** · Go **1.27.0**. D28 is landed and endorsed; not
to be revisited. The HN post is John's to submit.

Steering needed: no.
