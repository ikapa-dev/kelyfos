# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/49. **Phase 5 (hardening, v0.9) open**: P4-1/P4-2 promoted as P5-0…P5-5 (D27).
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.

## Now
P5-0 — `docs/hardening.md`: what a compromised agent reaches, before and after.

## This session
E1–E3 closed, **v0.6 released**; then the F-D33 batch and the E3→E4 seam check. Epic E4, all
nine tasks: the spec; serve-mcp with its ceiling; five file and state tools, which found the
MCP frame limit at 1 MiB against a promised 8 MiB (F-D38) and a restore held to no ceiling
(F-D39); the team tools (F-D42); the audit lane (F-D43); two client recipes (F-D44); the
plugins device and runtime (F-D45, F-D46). Exit: 22/22 checks, 11/11 recipes, three exams
whose 22 findings are in `docs/exam/`. **v0.7 tagged and published**, and the batch those
exams routed after it is done (F-D49). Epic E5, all eight: the v0.8 spec, named sessions,
diff and review, `kelyfos shell`, one refusal catalog whose acceptance found the plan's own
headline fix line never reaching the client (F-D53); inbound forwarding, proved by diffing
nftables with two forwards and none; a run history that is the records read back (F-D54);
`--notify`, best effort, data-never-script, off until asked.

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR per-arch not per-flavor: parked.

## The E4→E5 seam
## Toolchain
**Buildroot 2026.02.3 → 2025.02.17** (D28), the line buildroot.org itself lists as LTS, EOL
March 2028. It supports kernel header series only to 6.12, so the guest kernel went back
6.18.46 → **6.12.105** — kernel.org gives both the same projected EOL, December 2028, so the
move costs six release cycles and buys a supported build system. Full aarch64 rebuild, 117
acceptance checks across six suites and 14 recipes green; x86_64 and the boot/restore bars
are CI's, dispatched. Bubble Tea v2 landed earlier at the seam (F-D41/F-D51). The HN post is
John's.

Steering needed: no.
