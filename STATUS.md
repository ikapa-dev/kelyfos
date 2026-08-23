# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 34/42. **E1–E3 closed, v0.6 released. Epic E4 at 9/9.**

## Now
The E4 exit checklist, then tag v0.7 and publish.

## This session
E1–E3 closed and **v0.6 released**: a generated reference with CI failing on
drift, `llms.txt` at spec v2, CI-run recipes, a docs exam that found ten defects,
then the F-D33 batch and the seam check.

Epic E4, all nine tasks: the spec (F-D36, F-D37); serve-mcp with its ceiling
refusing in the E1-1 style; five file and state tools, which found the MCP frame
limit at 1 MiB against a promised 8 MiB (F-D38) and a restore held to no ceiling
(F-D39); the team tools, needing `team up` split (F-D42), which caught a write to
stdout — the protocol, on that path; the audit lane (F-D43); two client recipes,
which found a client-launched server could run with no ceiling (F-D44); the
plugins device (F-D45); the plugin runtime and its two fixes (F-D46); and both
doors at once, in CI. 11/11 recipes pass.

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR per-arch
  not per-flavor: parked. A live Claude Code session vs serve-mcp needs John.

## The E4→E5 seam: a platform-refresh pair (John's ruling)
Both F-D35 premises falsified. After E4's exit and v0.7, before E5-0:
1. **Buildroot → 2025.02.x**, superseding D11. Gates: both arches rebuilt, the
   acceptance suite, docs and cookbook green, boot and restore benchmarks re-run
   **on bare KVM** with the bars holding. Fallback: freeze on 2026.02.3, said
   truthfully in versions.mk (F-D40).
2. **Bubble Tea + Lip Gloss → v2**, superseding F-D23, timeboxed to one task.
   Acceptance: E2-8 watch re-run under a real PTY, identical behaviour, -race clean.
   Fallback: revert to frozen v1 with a new reopening condition (F-D41).
Buildroot first, then Bubble Tea, then the seam check, then E5-0. The HN post is
John's, and P4 stays parked unless he promotes it.

Steering needed: no.
