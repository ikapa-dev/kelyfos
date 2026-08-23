# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 25/42. **E1, E2, E3 closed. Epic E4 active, 0/9.**

## Now
Tag v0.6 and publish it the way v0.4 and v0.5 were published, then Epic E4:
`docs/mcp-surface.md` first, spec before code.

## This session
Refreshed the HN post to v0.5 (John's to send). E3-0: seven audits read every
doc against its code; `docs/README.md` is the entry map and F-D27 routed the
findings — corrections landed across seven documents. E3-1: `docs/reference/` is
generated from the product, CI fails on drift (F-D28). E3-2: `llms.txt` (spec v2,
conformance tested) + `llms-full.txt`. E3-3 and E3-4: eight cookbook recipes and
`docs/integrating.md`, each recipe run before it was written down — **8 passed, 0
failed**. E3-5: the docs-only exam **passed first try** and found ten defects,
nine of them fixed here (F-D29..32).

## Defects found, recorded not fixed (F-D27, F-D30)
- `kelyfos shim` opens no recorder and reads no `kelyfos.toml` — no audit record
  and no resource cap for a shim sandbox. Now documented as such.
- Plain-HTTP egress records `mode: tunnelled` though the proxy reads all of it —
  the one place D6's binding condition (2) does not hold. Documented, not fixed.
- `[team.agent.spawn.resources]` takes `idle_timeout`/`max_runtime` and enforces
  neither; `kelyfos fork` never writes `session.end`; `log --list` sorts by id.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- Per-agent `idle_timeout` still refused (F-D20); lifting it is its own task (F-D22).

## Waiting on John
The HN post (his to send). Whether P4 is promoted. Whether the four defects
above are fixed inside E3 or wait for their own epic.

Steering needed: no
