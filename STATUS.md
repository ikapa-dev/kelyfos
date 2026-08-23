# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 32/42. **E1–E3 closed, v0.6 released. Epic E4 at 7/9.**

## Now
E4-7 — the supervisor plugin runtime: launch each plugin, namespace its tools.

## This session
E1–E3 built and closed, **v0.6 released**: a generated reference with CI failing
on drift, `llms.txt` at spec v2, CI-run cookbook recipes, and a docs exam that
found ten defects. Then the F-D33 batch and the seam check.

Epic E4 so far. E4-0 the spec (F-D36, F-D37). E4-1 serve-mcp live, the ceiling
refusing in the E1-1 style. E4-2 five file and state tools: the MCP frame limit
was 1 MiB against a promised 8 MiB (F-D38), and a restore met no ceiling at all
(F-D39). E4-3 the team tools, needing `team up` split into raising and waiting
(F-D42), which caught a write to stdout — the protocol, on that path. E4-4 the
audit lane; E4-0's promise of one export holding both lanes was rewritten rather
than met (F-D43). E4-5 two client recipes, which found a client-launched server
could run with no ceiling (F-D44); 10/10 recipes pass. E4-6 the plugins device,
read-only and shared rather than copied across forks (F-D45).

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR is per-arch not per-flavor: parked.

## The E4→E5 seam: a platform-refresh pair (John's ruling)
Both F-D35 premises falsified. After E4's exit and v0.7, before E5-0:
1. **Buildroot → 2025.02.x**, superseding D11. Gates: both arches rebuilt, the
   acceptance suite, docs and cookbook green, and boot and restore benchmarks
   re-run **on the bare-KVM reference** with the bars holding. Fallback: stay
   frozen on 2026.02.3, said truthfully in versions.mk (F-D40).
2. **Bubble Tea + Lip Gloss → v2**, superseding F-D23, timeboxed to one task.
   Acceptance: E2-8 watch re-run under a real PTY, identical behaviour, -race
   clean. Fallback: revert to frozen v1 with a new reopening condition (F-D41).
Buildroot first, then Bubble Tea, then the seam check, then E5-0. The HN post is John's to send; P4 stays parked unless he promotes it.

Steering needed: no.
