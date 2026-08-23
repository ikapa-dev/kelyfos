# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T03:40Z · **HEAD** `cd21ee7` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 14/42
- **active** Epic E2 — Agent teams (v0.5), 5/10 · right now: starting E2-5, spawn under a budget

## Last three completed
- `cd21ee7` E2-4 — `kelyfos team up | ps | down`; three real VMs routing messages, a refused
  edge, an ask/reply round trip and the store, all in one verified chain. F-D17 on fork spawn
- `8fd997f` F-D16 — extend the parser rather than take a TOML library, with both checked
- `a39c2ed` E2-3 — the team store

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2 and E1-3 settled** on bare KVM (150% quota 1.52 cores; disk 19.08 MB/s; net 19.52 Mbps).
- **E1-3**: a guest raising `max_sectors_kb` past the bucket can reach at most 2× the rate.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13), bounded by `mem`.
- **E1-8**: an exact `disk_iops` figure is unproven — ext4 journal writes confound the count.
- **E2-4 / F-D17**: **the E2 acceptance bar of sub-second team spawn will not be met.** Agents
  boot concurrently rather than forking, because a fork is vsock-only (P3-2) and a team agent
  with an allowlist needs a NIC. Three concurrent boots took 2.34 s here against ~2.31 s
  sequential — this box is CPU-bound, so the reference runner decides what concurrency buys.

## Next three actions
1. E2-5 — spawn under a declared budget: the one sanctioned exception to a fixed topology, with
   the spawned worker attaching on exactly one edge, to its spawner.
2. E2-6 — the team cgroup hierarchy: per-agent E1-2 slices beneath a collective cap.
3. E2-7 — `log --verify` and `log --export team.html` over a whole team, with per-agent lanes.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act,
  his timing. It describes v0.3; v0.4 is now out and the post has not been updated for it.

Steering needed: no
