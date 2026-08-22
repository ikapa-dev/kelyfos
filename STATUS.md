# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.
Rewritten at every task boundary, in its own commit right after the work lands,
so the sha below is always a commit that exists.

- **as of** 2026-08-22T22:33Z · **HEAD** `966e0ab` · tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 3/42
- **active** Epic E1 — Resource governance (v0.4), 3/9 · right now: starting E1-3

## Last three completed
- `966e0ab` deps — `versions.mk` already current on all four pins; Go modules upgraded,
  `x/sys` v0.36.0 → v0.47.0 retires GO-2026-5024; govulncheck v1.7.0 clean; v2 TUI jump parked (D25)
- `9a36ad3` + `4dcbaff` CI chore — docs-only skip, Buildroot ccache keyed on `versions.mk`,
  weekly cache-free build (D24); run 32601143550 green end to end in 11.5 min
- `e73d63b` PLAN/PLAN-FEATURES: record the true stopping state

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- E1-2's CPU quota is proven only at 50%, where the cap sits below demand. This dev box cannot
  tell 150% from uncapped (nested virt caps guest demand at ~1 core, D15). **E1-8 is load-bearing**:
  it settles the 150%-vs-uncapped case with stress-ng on the bare-KVM CI reference.

## Next three actions
1. E1-3 — I/O throttling via Firecracker's token-bucket rate limiters on the NIC and both block
   devices; `net_mbps_rx/tx`, `disk_iops`, `disk_mbps` become enforced `[resources]` keys.
2. E1-4 — OOM visibility: supervisor watches `/dev/kmsg`, emits `resource.oom`, `run` exit
   distinguishes an OOM-kill from a crash.
3. E1-5 — scratch cap: `size=` on the tmpfs backing the overlay upper layer.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
