# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 17/42. E1 closed (v0.4). Epic E2 active, 8/10.

## Now
Epic E2 — agent teams (v0.5). Next task: **E2-8**, multi-lane `kelyfos watch`:
one lane per agent (exec activity, egress, resource use vs caps) plus a
message-flow ticker.

## New this session
- Parking lot +2 from Microsoft's Azure SRE Agent post (2026-08-21): per-call
  credential handles, output-side secret scrubbing. Neither is being built.
- **F-D19** records John's ruling on the fork fast path for no-egress agents.
- **E2-4 correction**: `allow`, `secrets`, `workspace`, `cpu_quota` were parsed
  per agent and dropped. Now applied; three combinations refused (F-D20).
- **E2-6** team cgroup hierarchy (F-D21). `dev/prove-team.sh` 6/6 green even
  nested — five guests generate demand a single sandbox cannot.
- **E2-7** one chain per team (F-D22), a lane per agent in the export. Two
  doc/code disagreements fixed: `team_reply` takes `correlate` not `id`, and
  `team.spawn` carries no budget field.

## Last two
- E2-7 the team transcript: one verifiable chain, exported as lanes.
- E2-6 the team's collective cap: one parent slice, agents beneath it.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- E2 acceptance "total spawn < 1 s": **measured** on bare KVM (D15) once the
  F-D19 fast path lands. Nested figures informational.
- Per-agent `idle_timeout` is still refused (F-D20) though E2-7 now supplies
  the signal it waited on; lifting it is its own task (F-D22).

## Next
E2-8 multi-lane watch → E2-9 demo + F-D19 fast path → E2 acceptance → v0.5 →
dependency-refresh check at the seam → Epic E3.

## Waiting on John
The HN post for v0.3/v0.4 (his to send). Whether P4 is ever promoted.

Steering needed: no
