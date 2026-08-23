# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T03:00Z · **HEAD** `a39c2ed` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 13/42
- **active** Epic E2 — Agent teams (v0.5), 4/10 · right now: starting E2-4, `kelyfos team up`

## Last three completed
- `a39c2ed` E2-3 — the team store: per-key rules that can only narrow access, absence
  distinguished from refusal, bounded, and every access recorded without the values
- `ab9392c` E2-2 — the seven team MCP tools and the guest end of the port-10102 channel
- `f9bb285` E2-1 — the broker: topology, routing, events; F-D15 for the new channel

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
- **E2-1/2/3**: everything in `internal/team` and the guest tools is proven by unit tests over
  in-memory channels. **Nothing has yet routed a message between two real VMs** — that is E2-4.

## Next three actions
1. E2-4 — `kelyfos team up | ps | down`. This is where the broker meets real VMs, and where the
   `[team]` toml has to be parsed: array-of-tables is beyond the hand-rolled parser, so the
   choice (extend it, or take a TOML dependency) needs a Decision Log entry written first.
2. E2-5 — spawn under a declared budget.
3. E2-6 — the team cgroup hierarchy, per-agent slices beneath a collective cap.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act,
  his timing. It describes v0.3; v0.4 is now out and the post has not been updated for it.

Steering needed: no
