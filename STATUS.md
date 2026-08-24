# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · CI green (run 32704409463)

## Plans
- PLAN.html — **39/50**. Phase 5 (hardening, v0.9): P5-0, P5-1, P5-2 done.
  P5-6 was added today by D30 and runs next.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.

## Now
P5-6 — the cgroup and the jail, composed. `kelyfos run --cpu-quota` is refused on every
jailed run on a systemd-user host: `Start`'s jailed branch never calls `WrapArgv`, so no
scope is created, and `--parent-cgroup` is passed only in direct mode. Fail-closed, not
silent. Must land before P5-4, which re-runs every suite.

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
- Measurement debt for P5-4: cold boot-to-ready and snapshot restore re-measured on the
  bare-KVM reference with jail and filter on the boot path, and the quickstart ≤5-min
  figure re-measured *including* the sudoers step.

## Toolchain
Buildroot **2025.02.17** (LTS, EOL March 2028) · Linux **6.12.105** (longterm, EOL
December 2028) · Firecracker **v1.16.1** · Go **1.27.0**. D28 is landed and endorsed; not
to be revisited. The HN post is John's to submit.

Steering needed: no.
