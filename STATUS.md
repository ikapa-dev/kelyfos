# KelyfOS — session status

Updated 2026-08-23 · tree clean, synced with origin/main

## Plans
- PLAN.html — 36/43. P4 backlog non-blocking, parked (P4-4/P4-5 [BLOCKED]).
- PLAN-FEATURES.html — 39/42. **E1–E4 closed, v0.7 released. Epic E5 at 5/8.**

## Now
E5-5 — inbound port forwarding over vsock, per F-D7 and `docs/qol.md` §4.

## This session
E1–E3 closed, **v0.6 released**; then the F-D33 batch and the E3→E4 seam check. Epic E4,
all nine tasks: the spec; serve-mcp with its ceiling refusing in the E1-1 style;
five file and state tools, which found the MCP frame limit at 1 MiB against a promised
8 MiB (F-D38) and a restore held to no ceiling (F-D39); the team tools (F-D42); the audit
lane (F-D43); two client recipes, which found a client-launched server could run with no
ceiling (F-D44); the plugins device and runtime (F-D45, F-D46); both doors at once, in CI.
Exit: 22/22 acceptance checks, 11/11 recipes, and three exams — two blind readers and John's
live client — whose 22 findings are in `docs/exam/`. **v0.7 tagged and published**, and the
batch those exams routed after it is done (F-D49). Epic E5 so far: the v0.8 spec, named
sessions, diff and review, `kelyfos shell`, and one refusal catalog whose acceptance found
the plan's own headline fix line never reaching the client (F-D53).

## Blocked / debts
- P4-4, P4-5 [BLOCKED]. `idle_timeout` refused (F-D20; F-D22). IMAGE_DIR per-arch not per-flavor: parked.

## The E4→E5 seam
**Bubble Tea + Lip Gloss v2: done** (F-D41 executed as F-D51) — five PTY checks, behaviour
identical to v1 by running both, `-race` clean two ways. **Kernel 6.18.46**, and the bump
found that a version change regenerated no config and rebuilt no kernel (F-D52); bars
re-earned on bare KVM: boot 69 ms, restore 33 ms. **Buildroot → 2025.02.x: queued** (F-D40)
— the origin 503s on the tarball, an upstream outage rather than this machine, and it timed
out again at this boundary. One HEAD per task boundary; the first 200 executes the hop with
every gate. `versions.mk` stays untouched until it lands, because its fallback sentence
would be untrue. After 14 days: any transport, verified against the signed `.sign`. The HN
post is John's.

Steering needed: no.
