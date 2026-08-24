# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **47/74**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35): every row now has a
  verdict and none will be ticked there. **Phase 6 open — "v1.0, the promise", 21 tasks**, drafted spec-first at P6-0.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-1 done.** The honesty sweep, and it was not the list P6-0 wrote: six parallel readers, each required to cite
the claim *and* the code refuting it, then an adversarial reconciler that re-checked every finding and **dropped
eight** — two as *unverified* rather than corrected on a guess. **59 verified claims** against the twelve known.

The three worst were **understatements**, which is the direction nobody audits for: `docs/threat-model.md`'s
summary table still said the jailer and guest confinement were "not yet", four releases after they shipped;
it said the audit record was absent under the shim, which F-D33 fixed; and `CONTRIBUTING.md` told a security
reporter KelyfOS is "pre-v0.1 and makes no hardened-security claims yet". Three were overstatements: the
generated profiles page said "nothing else is writable" while `/dev/shm` — a tmpfs sized at half the guest's RAM —
carries the same write rights as `/work`; the README claimed every `[resources]` cap is host-enforced when
`scratch` is applied by the guest's own kernel; and it promised a `resource.summary` on every session when only
`run` and team members emit one.

Generated pages were fixed **in their generator**, since a hand edit there is reverted by the next build. Four code
fixes came out of doc claims rather than the reverse — most notably the host argument summariser was missing
`data`, so base64 file contents could reach the record, and the supervisor's version was a constant reading
`0.2.0-p2`, printed on every boot and written into every chain for seven releases.

**Next: P6-2** — SECURITY.md with a real disclosure channel, and govulncheck promoted from a habit into CI.

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
