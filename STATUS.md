# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-22T23:10Z · **HEAD** `050022d` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 4/42
- **active** Epic E1 — Resource governance (v0.4), 4/9 · right now: starting E1-4

## Last three completed
- `050022d` E1-3 — Firecracker token-bucket limiters on the NIC and both block devices;
  bucket sizing settled by measurement (a small bucket is a wrong limit, not a tight one)
- `966e0ab` deps — `versions.mk` already current on all four pins; Go modules upgraded,
  `x/sys` v0.36.0 → v0.47.0 retires GO-2026-5024; v2 TUI jump parked (D25)
- `4dcbaff` + `9a36ad3` CI chore — docs-only skip, Buildroot ccache, weekly cache-free build (D24)

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- **E1-2**: CPU quota proven only at 50%, where the cap sits below demand. This box cannot tell
  150% from uncapped (nested virt caps guest demand at ~1 core, D15). **E1-8 is load-bearing.**
- **E1-3**: exact operations-per-second is unproven — an ext4 workload confounds the count with
  journal writes. The cap plainly binds (28× slowdown). E1-8's stress-ng settles the number.
- **E1-3**: a guest that raises its own `max_sectors_kb` past the bucket can provoke Firecracker's
  over-consumption path. Bounded at 2× the configured rate; documented, not fixed.

## Next three actions
1. E1-4 — OOM visibility: supervisor watches `/dev/kmsg`, emits `resource.oom`, `run` exit
   distinguishes an OOM-kill from a crash.
2. E1-5 — scratch cap: `size=` on the tmpfs backing the overlay upper layer.
3. E1-6 — time budgets: `--max-runtime` / `--idle-timeout`, `resource.timeout` audit event.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
