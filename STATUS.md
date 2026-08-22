# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T00:05Z · **HEAD** `d5d322a` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 6/42
- **active** Epic E1 — Resource governance (v0.4), 6/9 · right now: starting E1-6

## Last three completed
- `a4e9fe1` E1-5 — scratch cap: `size=` on the overlay tmpfs via `kelyfos.scratch=` on the kernel
  command line; `ENOSPC` at the cap, `/work` unaffected. F-D13: the one guest-applied cap, and why
- `9c197ac` + `d5d322a` CI — a concurrency group per commit on main; the first fix was insufficient
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
1. E1-6 — time budgets: `--max-runtime` / `--idle-timeout` + toml keys; SIGTERM → grace →
   workspace sync-back → teardown, plus a `resource.timeout` event naming which budget fired.
2. E1-7 — usage receipt: `kelyfos watch` resources lane + `resource.summary` at teardown.
3. E1-8 — enforcement proof: `stress-ng` in the dev flavor, driven against tight caps on the
   bare-KVM CI reference. Settles the E1-2 and E1-3 debts above.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
