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
**Bubble Tea + Lip Gloss v2: done** (F-D41 executed as F-D51) — five PTY checks, behaviour
identical to v1 by running both, `-race` clean two ways. **Kernel 6.18.46**, and the bump
found that a version change regenerated no config and rebuilt no kernel (F-D52); bars
re-earned on bare KVM: boot 69 ms, restore 33 ms. **Buildroot → 2025.02.x: queued** (F-D40)
— the origin 503s on the tarball, an upstream outage rather than this machine, and it timed
out again at this boundary. One HEAD per task boundary; the first 200 executes the hop with
every gate. `versions.mk` stays untouched until it lands, because its fallback sentence
would be untrue. After 14 days: any transport, verified against the signed `.sign`. The HN
post is John's.

Steering needed: no.
