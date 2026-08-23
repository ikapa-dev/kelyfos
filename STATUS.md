# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 20/42. **Epic E3 active, 1/6.**

## Now
E3-1 — `make docs`: generate the CLI, toml, MCP-tool, event and exit-code
reference from the source, and fail CI on any drift.

## This session
Refreshed `docs/launch/hn-post.md` to v0.5 (still John's to send). Then E3-0:
seven parallel audits read every doc against the code implementing it, and
`docs/README.md` is now the entry map — concept vs reference per document, plus
what has no documentation at all. F-D27 routed the findings; the prose
corrections have landed across seven documents, no behaviour changed.

## Code defects found, recorded not fixed (F-D27)
- `kelyfos shim` opens no recorder and reads no `kelyfos.toml` — a shim sandbox
  has neither an audit record nor a resource cap, which its own doc promises.
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
