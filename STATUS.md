# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 26/42. **E1–E3 closed, v0.6 released. Epic E4 active, 1/9.**

## Now
E4-1 — `kelyfos serve-mcp` core: the lifecycle tools, concurrent sandboxes with
ids, `max_sandboxes`, and ceilings refused in the E1-1 style.

## This session
Epic E3 built and closed, **v0.6 tagged and published**: a reference generated
from the product with CI failing on drift, `llms.txt` at spec v2 with conformance
tested, eight cookbook recipes each run before being written down,
`docs/integrating.md`, and a docs-only exam that **passed first try**, finding
ten defects (F-D28..32).

Then John's F-D33 hardening batch, six commits: the shim reads `kelyfos.toml`,
enforces caps and writes a recorder; plain HTTP records `mode: plain` rather than
claiming it was tunnelled; a bridge closing mid-call answers with an error, not
silence; the inert spawn-budget keys are refused; `fork` closes its sessions;
three smalls fixed, one parked (F-D34). 8/8 recipes still pass; CI caught a racy
test of mine that this machine hid. Then the seam check (F-D35) and E4-0's spec
(F-D36, F-D37).

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog. Per-agent `idle_timeout` still refused
  (F-D20); lifting it is its own task (F-D22).

## Waiting on John — two version-policy calls (F-D35)
1. **Buildroot.** D11 pinned 2026.02.3 as "the LTS line". buildroot.org now lists
   LTS as **2025.02.16**; 2026.02 is on no track and took no release when stable
   and LTS both did. Stay frozen, drop to an older supported LTS, or follow stable?
2. **Bubble Tea v1.** F-D23's third condition fired — no advisory, but v1 is
   dormant (bubbletea 11 months, lipgloss 17) while v2 ships. Taking it means
   rewriting `host/watch.go` on no task, plus a vanity module path. Now or not?
3. The HN post, still his to send. And whether P4 is ever promoted.

Steering needed: YES — the two calls above. Neither blocks E4.
