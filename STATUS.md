# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T00:45Z · **HEAD** `4cb0e3d` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 7/42
- **active** Epic E1 — Resource governance (v0.4), 7/9 · right now: starting E1-7

## Last three completed
- `4cb0e3d` E1-6 — time budgets (`--max-runtime`, `--idle-timeout`), `resource.timeout`, exit 124.
  Also fixed a v0.3 defect it uncovered: `run -- <cmd>` with a non-zero exit skipped teardown
  **and workspace sync-back** (`defer os.Exit` runs no other defers). Logged under P3-7
- `a4e9fe1` E1-5 — scratch cap on the overlay tmpfs; F-D13 on why this one is guest-applied
- `0e70023` E1-4 — `resource.oom`, events channel implemented, `run` exits 137. F-D12

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2**: CPU quota proven only at 50%. This box cannot tell 150% from uncapped (nested virt
  caps guest demand at ~1 core, D15). **E1-8 is load-bearing.**
- **E1-3**: exact operations-per-second unproven — ext4 journal writes confound the count. The
  cap plainly binds (28× slowdown). E1-8's stress-ng settles the number.
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can reach at most 2× the
  configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13). Bounded by `mem`, which is hardware.

## Next three actions
1. E1-7 — usage vs caps: a resources lane in `kelyfos watch` sampled from cgroup `cpu.stat` /
   `memory.current`, and a `resource.summary` receipt at teardown that `log --export` renders.
2. E1-8 — enforcement proof: `stress-ng` in the dev flavor, driven against tight caps on the
   bare-KVM CI reference. Settles the E1-2 and E1-3 debts above.
3. Epic E1 exit: full acceptance test, tag `v0.4`, publish the release as v0.3 was published.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
