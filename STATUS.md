# KelyfOS — run status

Heartbeat file. Current state only; history lives in the plan progress logs.

- **as of** 2026-08-22T21:53Z · **HEAD** `e73d63b` · working tree clean, `origin/main` == `HEAD`
- **PLAN.html** 36/43 (phases 0–3 done; P4 backlog, 2 blocked) · **PLAN-FEATURES.html** 3/42
- **active** Epic E1 — Resource governance (v0.4), 3/9 · right now: session start, pre-E1 chores

## Last three completed
- `e73d63b` PLAN/PLAN-FEATURES: record the true stopping state
- `3db8807` E1-2 — host CPU-time quota via cgroup v2 (F-D11: systemd scope when unprivileged)
- `9263788` E1-1 — docs/resources.md; `[resources]` becomes hard ceilings that refuse, not clamp

## Blocked
- **P4-4** browser flavor — task text says "if users ask for it"; no users yet
- **P4-5** EU-compliance decision gate — task text says "decide with evidence"; no evidence yet

## Measurement debts carried forward
- E1-2's CPU quota is proven only at 50%, where the cap sits below demand. This dev box cannot
  tell 150% from uncapped (nested virt caps guest demand at ~1 core, D15). **E1-8 is load-bearing**:
  it settles the 150%-vs-uncapped case with stress-ng on the bare-KVM CI reference.

## Next three actions
1. CI chore: docs-only path filter, Buildroot `dl/` + ccache caches keyed on `versions.mk`,
   weekly scheduled full-from-source build. One commit, CI green, logged in PLAN.html.
2. Dependency refresh: every pin in `versions.mk` vs upstream; `go list -m -u all` + `govulncheck`.
   One commit, bumps carry their new sha256 and a rationale; CI green after.
3. E1-3 — I/O throttling via Firecracker's native token-bucket rate limiters.

## Waiting on John
- The HN launch post (`docs/launch/hn-post.md`) is written and deliberately unposted — his act, his timing.

Steering needed: no
