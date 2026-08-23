# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 22/42. **Epic E3 active, 3/6.**

## Now
E3-3 — the cookbook: recipes that are literal scripts CI extracts and executes.

## This session
Refreshed `docs/launch/hn-post.md` to v0.5 (John's to send). E3-0: seven audits
read every doc against its code; `docs/README.md` is the entry map, F-D27 routed
the findings, prose corrections landed across seven documents. E3-1:
`docs/reference/` is generated from the product, CI fails on drift (F-D28).
E3-2: `llms.txt` (spec v2, conformance tested) and `llms-full.txt`, measured at
**48,285 tokens** — 24% of a 200k window (F-D29).

## Code defects found, recorded not fixed (F-D27)
- `kelyfos shim` opens no recorder and reads no `kelyfos.toml` — a shim sandbox
  has no audit record and no resource cap, which its own doc promised.
- Plain-HTTP egress records `mode: tunnelled` though the proxy reads all of it —
  the one place D6's binding condition (2) does not hold. Documented, not fixed.
- `[team.agent.spawn.resources]` takes `idle_timeout`/`max_runtime`, enforces
  neither. And `kelyfos fork` writes `session.start` and never `session.end`.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- Per-agent `idle_timeout` still refused (F-D20); lifting it is its own task (F-D22).

## Next
E3-1 → E3-2 llms.txt → E3-3 cookbook → E3-4 integration guide → E3-5 exam. v0.6.

## Waiting on John
The HN post (his to send). Whether P4 is promoted. Whether the four defects
above are fixed inside E3 or wait for their own epic.

Steering needed: no
