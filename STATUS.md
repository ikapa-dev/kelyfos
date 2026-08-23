# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 28/42. **E1–E3 closed, v0.6 released. Epic E4 at 3/9.**

## Now
E4-3 — team tools: `team_up`, `team_ps`, `team_down` over E2.

## This session
Epic E3 built and closed, **v0.6 tagged and published**: a reference generated
from the product with CI failing on drift, `llms.txt` at spec v2, eight cookbook
recipes each run before being written down, and a docs-only exam that **passed
first try**, finding ten defects (F-D28..32). Then John's F-D33 hardening batch,
six commits — the shim now goes through policy and the recorder, plain HTTP
records `mode: plain`, the inert spawn keys are refused (F-D34) — the seam check
(F-D35), and E4-0's spec (F-D36, F-D37).

E4-1 put serve-mcp live, the policy ceiling refusing in the E1-1 style. E4-2
added five tools and found two holes rather than new mechanism: the MCP frame
limit was 1 MiB while its tools promised 8 MiB, so reads over a megabyte died
with a bare EOF — one constant now, every reader and writer, proved at 8 MiB
(F-D38); and a restore met no ceiling at all, so snapshots record their size and
both allowlist ceilings are checked (F-D39).

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog. Per-agent `idle_timeout` still refused
  (F-D20; F-D22 is the task). IMAGE_DIR per-arch not per-flavor: parked.

## Waiting on John — two version-policy calls (F-D35)
1. **Buildroot.** D11 pinned 2026.02.3 as "the LTS line"; buildroot.org now lists
   LTS as **2025.02.16** and 2026.02 is on no track. Stay frozen, drop to an
   older supported LTS, or follow stable?
2. **Bubble Tea v1.** F-D23's third condition fired — no advisory, but v1 is
   dormant while v2 ships. Taking it means rewriting `host/watch.go` on no task.
3. The HN post is his to send; P4 stays parked unless he promotes it.

Steering needed: YES — the two calls above. Neither blocks E4.
