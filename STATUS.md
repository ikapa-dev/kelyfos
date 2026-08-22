# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T01:00Z · **HEAD** `e0b9615` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 8/42
- **active** Epic E1 — Resource governance (v0.4), 8/9 · right now: starting E1-8, the last task

## Last three completed
- `e0b9615` E1-7 — one host-side sampler feeding both a live `kelyfos watch` lane and a
  `resource.summary` receipt at teardown, each figure beside the cap it was consumed under. F-D14
- `4cb0e3d` E1-6 — time budgets, `resource.timeout`, exit 124; and fixed a v0.3 defect where
  `run -- <cmd>` with a non-zero exit skipped teardown **and workspace sync-back** (P3-7)
- `a4e9fe1` E1-5 — scratch cap on the overlay tmpfs (F-D13)

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2**: CPU quota proven only at 50%. This box cannot tell 150% from uncapped (nested virt
  caps guest demand at ~1 core, D15). **E1-8 settles this.**
- **E1-3**: exact operations-per-second unproven — ext4 journal writes confound the count. The
  cap plainly binds (28× slowdown). **E1-8 settles this.**
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can reach at most 2× the
  configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13). Bounded by `mem`, which is hardware.

## Next three actions
1. E1-8 — enforcement proof: add `stress-ng` to the dev flavor, drive CPU, memory, disk and
   network against tight caps, and verify from the host that each held. Bare-KVM CI is the
   binding environment (D15); this is where the two debts above are settled or reported as unmet.
2. Epic E1 acceptance test, run verbatim, evidence into the progress log.
3. Epic E1 exit: tag `v0.4` and publish the release the way v0.3 was published.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
