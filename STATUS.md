# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main
## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 16/42. E1 closed (v0.4). Epic E2 active, 7/10.

## Now
Epic E2 — agent teams (v0.5). Next task: **E2-7**, the team transcript:
`kelyfos log --verify` over the whole team chain, and `--export team.html`
rendering per-agent lanes with the message flow between them.

## New this session
- Parking lot +2 from Microsoft's Azure SRE Agent post (2026-08-21): per-call
  credential handles, output-side secret scrubbing. Neither is being built.
- **F-D19** records John's ruling on the fork fast path for no-egress agents.
- **E2-4 correction**: `allow`, `secrets`, `workspace` and `cpu_quota` were
  parsed per agent and then dropped on the floor. Now applied; three
  combinations refused at the file. F-D20 covers `idle_timeout`.
- **E2-6** team cgroup hierarchy, F-D21. `dev/prove-team.sh` is 6/6 green even
  nested — five guests generate demand a single sandbox cannot.

## Last two
- E2-6 the team's collective cap: one parent slice, per-agent slices beneath
  it, equal `cpu.weight`, measured on the parent's own `cpu.stat`.
- E2-5 spawn under a declared budget, host-enforced lifetime, all audited.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- E2 acceptance "total spawn < 1 s": **measured** on the bare-KVM reference
  (D15) once the F-D19 fast path lands. Nested figures informational.

## Next
E2-6 → E2-7 transcript → E2-8 multi-lane watch → E2-9 demo + F-D19 fast path →
E2 acceptance → v0.5 → dependency-refresh check at the seam → Epic E3.

## Waiting on John
The HN post for v0.3/v0.4 (his to send). Whether P4 is ever promoted.
Steering needed: no
