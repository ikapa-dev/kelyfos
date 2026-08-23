# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 25/42. **E1–E3 closed, v0.6 released. Epic E4 active, 0/9.**

## Now
E4-0 — `docs/mcp-surface.md`, spec before code. The seam dependency check is
done: every pin current, `govulncheck` clean (F-D35).

## This session
Epic E3 built and closed, **v0.6 tagged and published**. `docs/reference/` is
generated from the product with CI failing on drift (F-D28); `llms.txt` follows
spec v2 with conformance tested (F-D29); eight cookbook recipes, each run before
it was written down (F-D30); `docs/integrating.md` (F-D31); and the docs-only
exam **passed first try**, finding ten defects (F-D32).

## The F-D33 hardening batch — done
John's ruling after the exam, six commits. The shim reads `kelyfos.toml`,
enforces the caps and writes a recorder; plain HTTP records `mode: plain`
instead of claiming it was tunnelled; a bridge that closes mid-call answers with
an error instead of silence; the two inert spawn-budget keys are refused; `fork`
closes its sessions; three smalls fixed, one parked (F-D34). 8/8 recipes still
pass. CI caught a racy test of mine that this machine hid; fixed under `-race`.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- Per-agent `idle_timeout` still refused (F-D20); lifting it is its own task (F-D22).

## Waiting on John — two version-policy calls (F-D35)
1. **Buildroot.** D11 pinned 2026.02.3 as "the LTS line". buildroot.org now lists
   LTS as **2025.02.16**; 2026.02 is on no track and took no release when stable
   and LTS both did. Stay frozen, drop to an older supported LTS, or follow stable?
2. **Bubble Tea v1.** F-D23's third condition fired — no advisory, but v1 is
   dormant (bubbletea 11 months, lipgloss 17) while v2 ships. Taking it means
   rewriting `host/watch.go` on no task, plus a vanity module path. Now or not?

Also his: the HN post, and whether P4 is ever promoted.

Steering needed: YES — the two calls above. Neither blocks E4.
