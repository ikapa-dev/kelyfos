# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **47/74**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35): every row now has a
  verdict and none will be ticked there. **Phase 6 open — "v1.0, the promise", 21 tasks**, drafted spec-first at P6-0.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-2 done.** `SECURITY.md` exists. Its short half is how to report; its long half is **what is and is not a
vulnerability here**, which this project can state unusually precisely because it already publishes what it does
not defend — nine documented design decisions listed as *not* findings (root inside your own guest, the chroot not
being the boundary, the shared uid, `--no-jail`, side channels, the unsigned artifacts) against seven that are, the
sharpest being *a record that overstates the walls that were around a run*. The three documents that dead-ended at
"raise concerns privately with the maintainer" now point at it.

The channel is GitHub's private vulnerability reporting rather than a published address (D42) — and **it is one
owner toggle away**, so the document is written to be true either way: it names the button, and says what to do
when the button is not there. A SECURITY.md that would be wrong on the day it landed is what P6-1 just spent a
commit undoing. No response time is promised; a number a solo maintainer cannot keep is worse than none.

`govulncheck` is promoted from a habit into CI — it has caught a real advisory here before. Own workflow, own day,
fails the run rather than opening an issue, and deliberately *not* on every push. **§8 rule 8 is amended** in the
same commit: "the latest CI run" now means every workflow that gates main, because a rule that read only the build
would never see the one workflow built to go red when nothing changed.

Pin worth noting: `govulncheck` is **v1.7.0** from the module proxy. Its GitHub releases page stops at v1.1.4 in
January 2025 — reading the familiar page would have pinned a scanner nineteen months stale and called it current.

**Next: P6-3** — fuzz harnesses for every parser on a trust boundary, with the boundary named.

## Blocked / needs John
- **DCO.** `CONTRIBUTING.md` and the README require a `Signed-off-by`; 0 of the last 50 commits carry one and
  history cannot be rewritten. Sign from here on, gate only new commits, or amend the document. John's call.
- **Enable private vulnerability reporting** — Settings → Security, or
  `PUT /repos/p4r4n0rm4l/KelyfOS/private-vulnerability-reporting`. Reads `{"enabled":false}` today. One toggle,
  reversible, locks nothing. `SECURITY.md` names it as the channel and stays true until it is on, but the button
  a reporter needs is not there yet. **This is the highest-value single action on the list.**
- **Immutable releases** — worth having, but it locks published assets and protects tags, so it is a commitment.
  Note it attests *publication*, never build provenance; the two must never share a sentence (D39).
- **Dependabot security updates** are disabled. Noted rather than folded into P6-2: it opens pull requests rather
  than reporting, which is a different kind of thing to consent to.
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
- **Routed out of P6-1, not dropped:** the guest `os-release` still says `0.1.0-dev`. Fixing it needs the overlay
  templated and an image build to verify, so it goes to P6-9 where that build is already open. Also routed: the
  shim ignores `max_runtime`/`idle_timeout` (documented as a gap now, enforcement is a task); `resource.summary`
  is absent on four close paths; the nftables drop counter is read by nothing; policy-file and team-plan refusals
  carry no catalog ID.
- `llms-full.txt` is now **440,396 bytes, ~114k tokens** (estimated, not measured — a committed measurement
  command is P6-17).

## Toolchain
Buildroot **2025.02.17** · Linux **6.12.105** · Firecracker **v1.16.1** · Go **1.27.0**. MCP revision spoken:
**2025-11-25** (legacy era) — the current spec revision is 2026-07-28 and removes the `initialize` handshake
entirely; `docs/mcp-surface.md` made that deferral deliberately and P6-14 states the policy. The HN post is John's
to submit.

Steering needed: no.
