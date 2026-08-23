# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T02:10Z · **HEAD** `5917902` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 9/42
- **active** Epic E2 — Agent teams (v0.5), 0/10 · right now: E2-0, `docs/teams.md`

## Last three completed
- **Epic E1 closed and `v0.4` released** — caps proof 8/8 and the acceptance list 13/13 on the
  bare-KVM x86_64 reference; release verified from a clean install of the published artifacts
- `5917902` E1-8 — `stress-ng` in the dev flavor, `dev/prove-caps.sh`, `dev/accept-e1.sh`,
  `caps.yml`. Found a real cgroup bug (`controllers` vs `subtree_control`) and a test that was
  measuring its own instrument
- `e0b9615` E1-7 — usage lane + `resource.summary` receipt (F-D14)

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2 and E1-3 are settled**: 150% quota measured at 1.52 cores' worth against an uncapped
  3.97 on bare KVM; disk 19.08 MB/s and net 19.52 Mbps steady against 20 each.
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can reach at most 2× the
  configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13). Bounded by `mem`, which is hardware.
- **E1-8**: an exact operations-per-second figure for `disk_iops` is still unproven — an ext4
  workload confounds the count with journal writes. The cap plainly binds; the number does not.

## Next three actions
1. E2-0 — `docs/teams.md`, spec before code. A first draft landed early with `c76b2f6` while
   E1-8's CI was blocked; it needs its review pass, its progress row and its tick.
2. E2-1 — the host broker: route messages over the existing per-VM vsock channels, enforce the
   edge list, make every message and every refusal an event.
3. E2-2 — the six team MCP tools in the supervisor.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act,
  his timing. It describes v0.3; v0.4 is now out and the post has not been updated for it.

Steering needed: no
