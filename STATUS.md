# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 25/42. **E1–E3 closed, v0.6 released. Epic E4 active, 0/9.**

## Now
The dependency seam check (versions.mk vs upstream, `go list -m -u all`,
`govulncheck`), then E4-0 — `docs/mcp-surface.md`, spec before code.

## This session
Refreshed the HN post, now at v0.6 (John's to send). E3-0: seven audits read every
doc against its code; `docs/README.md` is the entry map and F-D27 routed the
findings — corrections landed across seven documents. E3-1: `docs/reference/` is
generated from the product, CI fails on drift (F-D28). E3-2: `llms.txt` (spec v2,
conformance tested) + `llms-full.txt`. E3-3 and E3-4: eight cookbook recipes and
`docs/integrating.md`, each recipe run before it was written down — **8 passed, 0
failed**. E3-5: the docs-only exam **passed first try** and found ten defects,
nine of them fixed here (F-D29..32). **v0.6 tagged and published.**

## The F-D33 hardening batch — done
John's ruling after the exam, six items, one commit each. The shim now reads
`kelyfos.toml`, enforces the caps and writes a recorder; plain HTTP records
`mode: plain` instead of claiming it was tunnelled; a bridge that closes
mid-call answers with an error instead of silence; the two inert spawn-budget
keys are refused; `fork` closes its sessions; and three smalls (list ordering,
report arrow, blank image). One parked in F-D34: refused-key line numbers.

## Blocked / debts
- P4-4, P4-5 [BLOCKED] — Phase 4 backlog, parked unless John promotes it.
- Per-agent `idle_timeout` still refused (F-D20); lifting it is its own task (F-D22).

## Waiting on John
The HN post (his to send). Whether P4 is promoted. Whether the four defects
above are fixed inside E3 or wait for their own epic.

Steering needed: no
