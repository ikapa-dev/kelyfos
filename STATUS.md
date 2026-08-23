# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 34/42. **E1–E4 closed; v0.7 released. Next: the seam.**

## Now
Seam check done (kernel 6.18.46, F-D52); the bench is re-earning the bars. Next:
E5-0. Buildroot is queued behind an upstream outage.

## This session
E1–E3 closed, **v0.6 released**; then the F-D33 batch and the E3→E4 seam check.

Epic E4, all nine tasks: the spec; serve-mcp with its ceiling refusing in the
E1-1 style; five file and state tools, which found the MCP frame limit at 1 MiB
against a promised 8 MiB (F-D38) and a restore held to no ceiling (F-D39); the
team tools, needing `team up` split (F-D42); the audit lane (F-D43); two client
recipes, which found a client-launched server could run with no ceiling (F-D44);
the plugins device and runtime (F-D45, F-D46); and both doors at once, in CI. Exit: 22/22 acceptance checks, 11/11 recipes, and
three exams — two blind readers and John's live client — whose 22 findings are in
`docs/exam/`. **v0.7 tagged and published**, and the batch those exams routed
after it is done (F-D49).

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR per-arch not per-flavor: parked.

## The E4→E5 seam
**Bubble Tea + Lip Gloss v2: done** (F-D41 executed as F-D51) — five PTY checks,
behaviour identical to v1 by running both, `-race` clean two ways. **Kernel
6.18.46**, and the bump found that a version change regenerated no config and
rebuilt no kernel (F-D52). **Buildroot → 2025.02.x: queued** (F-D40) — the origin
503s on the tarball, an upstream outage rather than this machine. One HEAD per
task boundary; the first 200 executes the hop with every gate. `versions.mk`
stays untouched until it lands, because its fallback sentence would be untrue.
After 14 days: any transport, verified against the PGP-signed `.sign`.
The HN post is John's.

Steering needed: no.
