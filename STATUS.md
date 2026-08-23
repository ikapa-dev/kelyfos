# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 19/42. **E1 and E2 closed. Epic E3 active, 0/6.**

## Now
**v0.5 is tagged and released.** John's ruling on F-D25 landed after it, as
F-D26: team spawn is cold-first, fork-warm. Awaiting the re-measurement on the
reference (caps run 32632420532), then E3-0.

## This session (see the progress log for the full account)
Epic E2 finished and released as v0.5: E2-4's correction, E2-6 cgroup hierarchy,
E2-7 one chain per team, E2-8 multi-lane watch, E2-9 demo + the fork path, the
acceptance list on the reference, then F-D26's cold-first rework.

## Epic E2 acceptance — the honest result
Seven of eight steps pass on the reference. **Step 1's "total spawn < 1 s" was
NOT met: 1098 ms** (recorded, never to be rewritten). 927 ms of it was writing
the fork template; a cold boot there is 109–134 ms, so the fork path was what
missed it (F-D25). John ruled: cold-first, fork-warm (F-D26). Re-measurement of
both paths on the reference is owed to the log from run 32632420532.

## Proofs (reference, run 32630824099, pre-F-D26)
`prove-caps` 8/0/0 · `prove-team` 6/0/0 · `demo-team` 20/0/1 · `accept-e1`
13/0/0 · `go test -race` green · `govulncheck` clean.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- The re-measurement above. Nested figures after F-D26: cold 3855 ms, warm
  1338 ms; the reference numbers are owed.
- Per-agent `idle_timeout` still refused (F-D20) though E2-7 supplies the
  signal; lifting it is its own task (F-D22).

## Next
v0.5 → E3-0 inventory → E3-1 generated reference → E3-2 llms.txt → E3-3
cookbook → E3-4 integration guide → E3-5 the docs-only exam.

## Waiting on John
The HN post (his to send). Whether P4 is ever promoted.

Steering needed: no
