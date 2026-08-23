# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 34/42. **E1–E3 closed, v0.6 released. Epic E4 at 9/9.**

## Now
Tag v0.7 and publish; then the post-tag hardening batch, then the seam pair.

## This session
E1–E3 closed, **v0.6 released**; then the F-D33 batch and the E3→E4 seam check.

Epic E4, all nine tasks: the spec (F-D36, F-D37); serve-mcp with its ceiling
refusing in the E1-1 style; five file and state tools, which found the MCP frame
limit at 1 MiB against a promised 8 MiB (F-D38) and a restore held to no ceiling
(F-D39); the team tools, needing `team up` split (F-D42); the audit lane (F-D43);
two client recipes, which found a client-launched server could run with no ceiling
(F-D44); the plugins device (F-D45); the plugin runtime and its two fixes (F-D46);
and both doors at once, in CI.

Exit: 22/22 acceptance checks, 11/11 recipes, and three exams — two blind readers
and John's live client — whose 22 findings are in `docs/exam/` (F-D47, F-D48).

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR per-arch not per-flavor: parked.
- Post-tag batch, from the exit exams: serve-mcp ignores a declared `[sandbox]
  workspace` in silence; a plugin tool colliding with a built-in is shadowed, not
  refused; `plugin.call` carries no arguments.

## The E4→E5 seam: a platform-refresh pair (John's ruling)
Both F-D35 premises falsified. After E4's exit and v0.7, before E5-0:
1. **Buildroot → 2025.02.x**, superseding D11. Gates: both arches rebuilt, the
   acceptance suite, docs and cookbook green, and the boot and restore benchmarks
   re-run **on bare KVM** with the bars holding. Fallback: freeze (F-D40).
2. **Bubble Tea + Lip Gloss → v2**, superseding F-D23, timeboxed to one task.
   Acceptance: E2-8 watch re-run under a real PTY, identical behaviour, -race
   clean. Fallback: frozen v1 with a new reopening condition (F-D41).
Buildroot first, then Bubble Tea, then the seam check, then E5-0. The HN post is John's.

Steering needed: no.
