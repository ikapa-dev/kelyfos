# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-23T02:00Z · **HEAD** `4198722` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 8/42
- **active** Epic E1 — Resource governance (v0.4), 8/9 · right now: E1-8 done in substance,
  waiting on the bare-KVM `caps` run for the binding numbers before ticking it

## Last three completed
- `4198722` E1 acceptance script green, 13/13 locally; found and fixed a misleading receipt
  label (peak RSS is the VMM's, not the guest's — it can exceed `mem` legitimately)
- `3fc35a6` E1-8 — stress-ng in the dev flavor, `dev/prove-caps.sh`, `caps.yml` on bare KVM
- `e0b9615` E1-7 — usage lane + `resource.summary` receipt (F-D14)

## In flight
- CI run 32607229850 (`caps`, x86_64, bare KVM) — the binding enforcement numbers. Local run
  was 7 passed / 0 failed / 1 skipped, the skip being the 150% quota, untestable under nested
  virtualisation. **This run is what settles the E1-2 measurement debt.**

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2/E1-3**: settled or reported by the caps run above, not before.
- **E1-3**: a guest raising its own `max_sectors_kb` past the bucket can reach at most 2× the
  configured rate; documented, not fixed.
- **E1-4**: a fork-to-write window leaves a child briefly OOM-exempt. Measured as unreachable.
- **E1-5**: `scratch` is applied by the guest kernel (F-D13). Bounded by `mem`, which is hardware.

## Next three actions
1. Read the `caps` run; tick E1-8 with its numbers, or record honestly what it did not show.
2. Close Epic E1: acceptance evidence into the progress log, epic marked done, E2 made active.
3. Tag `v0.4` and publish the release the way v0.3 was published (both arches, dev images,
   static CLIs, SHA256SUMS).

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
