# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 18/42. E1 closed (v0.4). Epic E2 active, 9/10.

## Now
Epic E2 — agent teams (v0.5). Next task: **E2-9**, the scripted proof demo —
and with it the F-D19 fork fast path, so the spawn bar has something to
measure. Then E2 acceptance, the exit checklist and v0.5.

## New this session
- Parking lot +2 from Microsoft's Azure SRE Agent post: per-call credential
  handles, output-side secret scrubbing. Neither is being built.
- **F-D19** John's ruling on the fork fast path for no-egress agents.
- **E2-4 correction**: `allow`, `secrets`, `workspace`, `cpu_quota` were parsed
  per agent and dropped. Now applied; three combinations refused (F-D20).
- **E2-6** team cgroup hierarchy (F-D21); `dev/prove-team.sh` 6/6 green.
- **E2-7** one chain per team (F-D22), lanes in the export. Two doc/code
  disagreements fixed: `team_reply` takes `correlate`; `team.spawn` has no
  budget field.
- **E2-8** multi-lane `kelyfos watch`. F-D23 declines the Bubble Tea v2 move
  D25 parked for this task. `go list -m -u all` and `govulncheck` clean.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- E2 acceptance "total spawn < 1 s": **measured** on bare KVM (D15) once the
  F-D19 fast path lands. Nested figures informational.
- Per-agent `idle_timeout` still refused (F-D20) though E2-7 supplies the
  signal it waited on; lifting it is its own task (F-D22).
- Dependency refresh half done: `go list -m -u all` + `govulncheck` run clean
  (F-D23). The versions.mk pins vs upstream are still to check at the seam.

## Next
E2-9 demo + F-D19 fast path → E2 acceptance → exit checklist → v0.5 →
finish the dependency refresh → Epic E3.

## Waiting on John
The HN post for v0.3/v0.4 (his to send). Whether P4 is ever promoted.

Steering needed: no
