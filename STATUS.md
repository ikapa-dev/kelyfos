# KelyfOS — session status

Updated 2026-08-24 · tree clean at session start, synced with origin/main (4c8fa5b)

## Plans
- PLAN.html — 38/49. **Phase 5 (hardening, v0.9)**: P5-0, P5-1 done — the VMM is jailed.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.

## Now
P5-2 — the host syscall filter. Three verbs in the task: establish *which* filter is in
force, prove it is on rather than trusting a default, record what it permits. P5-1 already
observes `Seccomp: 2` on the VMM from the host's `/proc`; the rest is this task.

## This session
Start-up reconciliation done: tree clean, `main` == `origin/main` at 4c8fa5b, 38/49 boxes,
v0.8 the latest release, Phase 5 active. Read CLAUDE.md, PLAN.html (§8 protocol, Phase 5,
D27–D29, newest progress rows), docs/hardening.md, STATUS.md. CLI rebuilt at 4c8fa5b;
`kelyfos-dev` Lima VM up, KVM present, Firecracker/Jailer v1.16.1, passwordless sudo
in place, aarch64 (dev flavor, Buildroot 2025.02.17 / Linux 6.12.105) and x86_64 images
present in the cache.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] on their own written conditions. `idle_timeout` refused (F-D20;
  F-D22). IMAGE_DIR per-arch not per-flavor: parked.
- Measurement debt carried into P5-4: cold boot-to-ready and snapshot restore must be
  re-measured on the bare-KVM reference (D15) with the jail and the filter on the boot
  path, and the quickstart ≤5-min figure re-measured *including* the sudoers step.

## Toolchain
Buildroot **2025.02.17** (LTS, EOL March 2028) · Linux **6.12.105** (longterm, projected
EOL December 2028) · Firecracker **v1.16.1** · Go **1.27.0**. The D28 hop is landed and
retroactively endorsed; not to be revisited. The HN post is John's to submit.

Steering needed: no.
