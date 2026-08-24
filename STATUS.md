# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **47/74**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35): every row now has a
  verdict and none will be ticked there. **Phase 6 open — "v1.0, the promise", 21 tasks**, drafted spec-first at P6-0.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-0 done.** Phase 6 drafted into PLAN.html against the code rather than against the backlog's wording — eleven
parallel audits plus two adversarial critics, whose verdict is recorded in D34 because acting on it *is* the
decision: as briefed this was three to four phases wearing one phase's name, and two pillars would have produced
claims this project cannot honestly make. Every pillar is in; three are scoped down with the case in a decision row
(D36 credential handles, D37 output scrubbing, D38 reproducibility), and P4-7's own "same commands everywhere"
sentence is retired because an interrupt does not cross `limactl shell` and losing it orphans a microVM and discards
the workspace (D35). §8 gained **rule 9** — documentation rides with the task — which is F-D9 restated in the
governing document after it evaporated with the file that held it (D40).

John's addition — **`kelyfos connect <client>`** — is folded in as P6-13 under the adoption pillar, sequenced after
P6-12 because the macOS launch path is whatever doctor's architecture makes correct. The client landscape was
surveyed live: **six supported** (Claude Code, Codex CLI, Cursor, VS Code, Gemini CLI, JetBrains Junie), the rest
generic, four rejected on evidence — two archived, one retired as a brand, one with 48k stars and no MCP
implementation. D41 has the list and the rule that matters: **one template with a swapped key is impossible**,
because Claude Code has no working-directory field at all and the others expand variables differently, so half of
them would silently attach the wrong policy under a shared snippet — F-D44's failure, once per client.

**Next: P6-1, the honesty sweep.** Every claim this repository makes that it has not earned, withdrawn before a 1.0
is built on top of it. The audit found them in numbers, and two are on the highest-traffic pages: the three
byte-identity claims (the shipped v0.9 kernels name two different build hosts, one of them a laptop), `llms.txt`'s
*generated* "not hardened yet" — so the drift gate has kept a retracted claim consistently wrong — the two client-configuration blocks
the repo prints for a stranger to copy (`integrating.md` calls its block `.mcp.json` "verbatim" and it has not been
since F-D48; the README claims the same in substance) — both naming the *inward* bridge with no `--policy`, `docs/protocol.md` §7's
host-side check that no code performs, and the generated CLI reference's silent loss of one-letter boolean flags,
which the gate structurally cannot see because generator and file agree and both are wrong.

## Blocked / needs John
- **DCO.** `CONTRIBUTING.md` and the README require a `Signed-off-by`; 0 of the last 50 commits carry one and
  history cannot be rewritten. Sign from here on, gate only new commits, or amend the document. John's call.
- **A security contact** for `SECURITY.md`, or the private-reporting channel enabled. Three documents currently tell
  a reporter to contact the maintainer privately and none says how — the most visible dead end in the repo.
- **Immutable releases** — worth having, but it locks published assets and protects tags, so it is a commitment.
  Note it attests *publication*, never build provenance; the two must never share a sentence (D39).
- **Dependabot security updates** are disabled.
- **macOS distribution**: raw download (Gatekeeper quarantines it) or a package manager — and whether a signing
  identity exists.
- P4-4, P4-5 **[BLOCKED]**, re-verified 2026-08-24: 0 stars, 0 forks, 0 issues, discussions off. Now dated rather
  than eternal — revisit 30 days after the v1.0 launch, since this phase's own exit is the act most likely to
  change those facts.

## Debts carried into Phase 6
- Two figures in the *previous* STATUS.md were stale and are corrected here: the five-agent pair is **412 ms cold /
  286 ms forked** on `demo-team`'s graph, not `prove-team`'s CPU-capped 737/149; and the macOS quickstart is not one
  number — **10 s is KelyfOS's own part**, the Linux layer was 28 s warm and 138 s cold and that part is Lima's.
- No release workflow exists; every release so far was cut by hand from a laptop. P6-8.
- `kelyfos runs --all` counts an unreadable session directory as missing rather than reporting it.
- On x86_64 the VMM carries a fifth KVM-created task; the filter check requires it to report filter mode.
- The E2B SDK smoke test (§1 criterion 5) was run once by hand in August: no suite, no CI job, no HTTP test. P6-18.

## Toolchain
Buildroot **2025.02.17** · Linux **6.12.105** · Firecracker **v1.16.1** · Go **1.27.0**. MCP revision spoken:
**2025-11-25** (legacy era) — the current spec revision is 2026-07-28 and removes the `initialize` handshake
entirely; `docs/mcp-surface.md` made that deferral deliberately and P6-14 states the policy. The HN post is John's
to submit.

Steering needed: no.
