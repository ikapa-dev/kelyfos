# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T02:20Z · **HEAD** `7293ba8` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 10/42
- **active** Epic E2 — Agent teams (v0.5), 1/10 · right now: starting E2-1, the host broker

## Last three completed
- `7293ba8` E2-0 — `docs/teams.md`: toml schema, six broker primitives, at-most-once delivery,
  and a threat-model section that quotes the nftables rules rather than asserting them
- **Epic E1 closed, `v0.4` released** — caps 8/8 and acceptance 13/13 on bare-KVM x86_64;
  the release verified from a clean install of the published artifacts
- `5917902` E1-8 — the proof scripts, and the cgroup bug and instrument bug they found

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2 and E1-3 settled** on bare KVM: 150% quota measured at 1.52 cores' worth against an
  uncapped 3.97; disk 19.08 MB/s and net 19.52 Mbps steady against 20 each.
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can reach at most 2× the
  configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13). Bounded by `mem`, which is hardware.
- **E1-8**: an exact operations-per-second figure for `disk_iops` is unproven — an ext4 workload
  confounds the count with journal writes. The cap plainly binds; the number does not.

## Next three actions
1. E2-1 — the host broker: route messages between VM supervisors over the existing per-VM vsock
   channels, enforce the edge list, and make every message and every refusal an event.
2. E2-2 — the six team MCP tools in the supervisor, so a model sees questions as tool calls.
3. E2-3 — the permissioned team store.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act,
  his timing. It describes v0.3; v0.4 is now out and the post has not been updated for it.

Steering needed: no
