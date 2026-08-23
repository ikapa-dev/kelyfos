# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T02:35Z · **HEAD** `f9bb285` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 11/42
- **active** Epic E2 — Agent teams (v0.5), 2/10 · right now: starting E2-2, the guest tools

## Last three completed
- `f9bb285` E2-1 — `internal/team`: topology, broker, events; a reply's correlation tag stands
  in for the edge it crosses; new guest→host channel on port 10102 (F-D15). Green under `-race`
- `7293ba8` E2-0 — `docs/teams.md`, spec before code
- **Epic E1 closed, `v0.4` released** — caps 8/8 and acceptance 13/13 on bare-KVM x86_64

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2 and E1-3 settled** on bare KVM: 150% quota at 1.52 cores' worth against an uncapped
  3.97; disk 19.08 MB/s and net 19.52 Mbps steady against 20 each.
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can reach at most 2× the
  configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13). Bounded by `mem`, which is hardware.
- **E1-8**: an exact operations-per-second figure for `disk_iops` is unproven — an ext4 workload
  confounds the count with journal writes. The cap plainly binds; the number does not.
- **E2-1**: the broker is proven by unit tests over in-memory channels. Nothing has yet routed a
  message between two real VMs — that is E2-4's `team up`, and until then the wiring is untested.

## Next three actions
1. E2-2 — the six team MCP tools in the supervisor, and the guest end of the port-10102 channel,
   so an incoming question reaches a model as an ordinary tool call.
2. E2-3 — the permissioned team store.
3. E2-4 — `kelyfos team up | ps | down`, which is where the broker first meets real VMs. The
   `[team]` toml needs array-of-tables, which the hand-rolled parser cannot do yet: that choice
   (extend it, or take a TOML dependency) is a Decision Log entry waiting to be written.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act,
  his timing. It describes v0.3; v0.4 is now out and the post has not been updated for it.

Steering needed: no
