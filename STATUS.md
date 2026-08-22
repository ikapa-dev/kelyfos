# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-22T23:35Z · **HEAD** `0e70023` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 5/42
- **active** Epic E1 — Resource governance (v0.4), 5/9 · right now: starting E1-5

## Last three completed
- `0e70023` E1-4 — `resource.oom` from the supervisor's `/dev/kmsg` watch; events channel (port
  10101) implemented at both ends; `run` exits 137. F-D12: exempt PID 1, restore every child
- `c0fd19d` P2-6 — fixed a 1-in-10 flaky test in the secret-injection suite; 0 failures in 60
- `050022d` E1-3 — Firecracker token-bucket limiters on the NIC and both block devices

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2**: CPU quota proven only at 50%. This box cannot tell 150% from uncapped (nested virt
  caps guest demand at ~1 core, D15). **E1-8 is load-bearing.**
- **E1-3**: exact operations-per-second unproven — an ext4 workload confounds the count with
  journal writes. The cap plainly binds (28× slowdown). E1-8's stress-ng settles the number.
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can provoke Firecracker's
  over-consumption path. Bounded at 2× the configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable —
  a command reading its own `oom_score_adj` first thing already reads 0 — but it is a window.

## Next three actions
1. E1-5 — scratch cap: `size=` on the tmpfs backing the overlay upper layer, defaulting to
   50% of the guest's RAM, with `ENOSPC` at the cap instead of eating the RAM budget.
2. E1-6 — time budgets: `--max-runtime` / `--idle-timeout`, `resource.timeout` audit event.
3. E1-7 — usage receipt: `kelyfos watch` resources lane + `resource.summary` at teardown.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
