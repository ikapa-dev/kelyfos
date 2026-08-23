# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 21/42. **Epic E3 active, 2/6.**

## Now
E3-2 — `llms.txt` per the llmstxt.org spec plus `llms-full.txt`: the whole
product in one file, token count measured and logged.

## This session
Refreshed `docs/launch/hn-post.md` to v0.5 (John's to send). E3-0: seven parallel
audits read every doc against the code implementing it; `docs/README.md` is the
entry map, and F-D27 routed what they found — prose corrections landed across
seven documents. E3-1: `docs/reference/` is generated from the product itself and
CI fails on drift (F-D28).

## Code defects found, recorded not fixed (F-D27)
- `kelyfos shim` opens no recorder and reads no `kelyfos.toml` — a shim sandbox
  has no audit record and no resource cap, which its own doc promised.
- Plain-HTTP egress records `mode: tunnelled` though the proxy reads all of it —
  the one place D6's binding condition (2) does not hold.
- `[team.agent.spawn.resources]` takes `idle_timeout`/`max_runtime`, enforces neither.
- `kelyfos fork` writes `session.start` and never `session.end`.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- Per-agent `idle_timeout` still refused (F-D20); lifting it is its own task (F-D22).

## Next
E3-1 → E3-2 llms.txt → E3-3 cookbook → E3-4 integration guide → E3-5 exam. v0.6.

## Waiting on John
The HN post (his to send). Whether P4 is promoted. Whether the four defects
above are fixed inside E3 or wait for their own epic.

Steering needed: no
