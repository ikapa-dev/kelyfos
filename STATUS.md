# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 29/42. **E1–E3 closed, v0.6 released. Epic E4 at 4/9.**

## Now
E4-4 — the outward audit lane: `mcp.host.*` events for every client tool call.

## This session
Epic E3 built and closed, **v0.6 tagged and published**: a generated reference
with CI failing on drift, `llms.txt` at spec v2, eight cookbook recipes each run
before being written down, and a docs exam that passed first try and found ten
defects. Then the F-D33 hardening batch, the seam check, and E4-0's spec.

E4-1 put serve-mcp live, the ceiling refusing in the E1-1 style. E4-2 added five
tools and found two holes: the MCP frame limit was 1 MiB while its tools promised
8 MiB (F-D38), and a restore met no ceiling at all (F-D39). E4-3 split `team up`
into raising and waiting so both doors raise a team the same way (F-D42); its
first live run caught a write to stdout — the protocol, on that path — and a race
in my own buffering. Five agents up in 1.3 s, down in 280 ms, `-race` clean.

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR is per-arch not per-flavor: parked.

## The E4→E5 seam carries a platform-refresh pair (John's ruling)
Both F-D35 premises accepted as falsified. After E4's exit and v0.7, before E5-0:
1. **Buildroot → 2025.02.x**, superseding D11. Gates: both arches rebuilt,
   acceptance suite, docs and cookbook green, boot and restore benchmarks re-run
   **on the bare-KVM reference** with the bars holding. Fallback: stay frozen on
   2026.02.3 and say so truthfully in versions.mk (F-D40).
2. **Bubble Tea + Lip Gloss → v2**, superseding F-D23, timeboxed to one task.
   Acceptance: E2-8 watch re-run under a real PTY, identical behaviour, -race
   clean. Fallback: revert to frozen v1 with a new reopening condition (F-D41).
Buildroot first, then Bubble Tea, then the seam check, then E5-0. The HN post is
still John's to send; P4 stays parked unless he promotes it.

Steering needed: no.
