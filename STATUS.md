# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **54/81**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35). **Phase 6 open —
  "v1.0, the promise", now 28 tasks**: an external security audit arrived mid-phase and added seven (D45).
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**An external security audit of `babec8f` arrived** — 23 findings, 1 critical, 6 high, 9 medium, 7 low. D45 is its
receipt and its plan, and **v1.0 does not tag until its trust-boundary group is closed and proven**: C-1, H-1 and
H-2 are one defect wearing three hats. The workspace block device is a guest→host surface and §5's trust-boundary
table does not list it — the table calls guest→host "Firecracker + KVM", which is true of the VM and silent about
the disk the VM writes and the host then reads with `debugfs`. Seven tasks, P6-21 to P6-27, inserted before P6-7
because list position is work order.

**P6-21 done (M-3).** `--review` no longer destroys an edit somebody made while they were reading the review.
`Stage` fingerprinted, a person read the diff for as long as they took, and `Commit` renamed that directory away
without looking again. It looks again now, and `.kelyfos-previous` is kept until the next successful run rather
than deleted one statement after the swap that made it worth having.

**P6-6 was corrected twice, by two reviews that found different things.** The design review found a false claim and
an unchecked value; the diff review found five more, four of them regressions P6-6 itself introduced.
- **The false claim**: a chain cut short at its *end* still verifies — nothing after the cut exists to break — and
  the footer said verification proves no line was removed. Withdrawn from the page, `docs/events.md` and the
  cookbook. `verify` now *observes* whether a record ends with `session.end`, as an observation and never a
  verdict, because "no end event" is an open session as often as a truncated one.
- **The unchecked value**: the page could state any chain head at all and `verify` said "chain intact". The head is
  the one number this product tells a reader to write down and compare against one they were given separately, so
  a file able to change it quietly turns that instruction into a trap. Head, event count and session id are marked,
  read back and compared now; a missing marker fails too. The **timeline stays unchecked** and the page says so.
- **The regressions**: a failed export truncated the report already at that path (25 bytes → 0); the summary
  printed the verified *prefix* as the event count; an empty record printed a blank head and advertised a check
  that refused the file; `log --verify` called an empty chain intact against the exit-code table P6-6 had just
  edited; and a 0-byte recorder was refused as "not a flight recorder".

**Two lessons worth keeping.** Reviewing the design and reviewing the diff are different jobs — running only the
first would have shipped four regressions, running only the second would have shipped the false claim. And
`main` went red once on the way, on the drift gate: P6-21 edited `docs/qol.md` without regenerating
`llms-full.txt`. §8 rule 9 exists for exactly that and caught it in one commit.

**Next: P6-22** — the hostile corpus and its CI job, before any boundary fix, so every finding is a failing test
before it is a fixed one. The finding under the findings: this project has nineteen fuzz targets and, until P6-6
put one on a file a stranger sends, every one of them fed a parser a *host-authored* string. None was a guest→host
path, and the guest is the untrusted party.

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
- **Cleared by P6-6:** `docs/events.md` §3's "adding a field is not breaking" is true now and says it was false
  until v1.0; §2's "verification re-serializes each parsed event" was stale after the fix and is corrected; the
  conformance table no longer points the verifiable export at the dead id P4-3.
- **The rendering gap is open by design and permanent, and now narrower than it was.** The values the page
  *states* about its record — head, event count, session id — are checked. Its *drawing* of the events is not, and
  will not be: the list of things to compare in a timeline has no end, and a partial answer would invite a reader
  to treat the rest as checked. `--replay` is what a reader uses instead.
- **A record cut short at its end verifies and cannot be distinguished from an open session.** Nothing keyless
  closes it — the head compared against one obtained separately is the only answer, and signing it is P6-7. The
  product says so on the page, in `verify`'s output and in `docs/events.md` rather than implying otherwise.
- **`Verify` still ignores `v` and does not check that every event carries the same `sandbox`.** A changed one is
  caught (both fields are inside the digest); a chain written with mixed ids from the start is not. Named here
  rather than fixed, because it belongs with P6-14's freeze of what the record promises.
- **Every `snapshot restore` session recorded before this phase is missing its egress events entirely.** Belongs in
  the upgrade guide, P6-16.
- Pre-existing and unfixed: `args = ["server.js", "--x=a,b"]` in a `[[plugin]]` block fails to load, because the
  toml array parser splits on the comma before parsing quotes. Same cause as the cut method syntax.
- `kelyfos snapshot restore` never reads `kelyfos.toml` at all — no ceilings, no allow, no secrets from the file.
  Defensible, undocumented, and a question P6-14's promise has to answer.
- The five-agent pair is **412 ms cold / 286 ms forked** on `demo-team`'s graph, not `prove-team`'s CPU-capped
  737/149; and the macOS quickstart is not one number — **10 s is KelyfOS's own part**, the Linux layer was 28 s
  warm and 138 s cold and that part is Lima's.
- No release workflow exists; every release so far was cut by hand from a laptop. P6-8.
- `kelyfos runs --all` counts an unreadable session directory as missing rather than reporting it.
- On x86_64 the VMM carries a fifth KVM-created task; the filter check requires it to report filter mode.
- The E2B SDK smoke test (§1 criterion 5) was run once by hand in August: no suite, no CI job, no HTTP test. P6-18.
- **Routed out of P6-1, not dropped:** the guest `os-release` still says `0.1.0-dev`. Fixing it needs the overlay
  templated and an image build to verify, so it goes to P6-9 where that build is already open. Also routed: the
  shim ignores `max_runtime`/`idle_timeout` (documented as a gap now, enforcement is a task); `resource.summary`
  is absent on four close paths; the nftables drop counter is read by nothing; policy-file and team-plan refusals
  carry no catalog ID.
- The two MCP argument summarisers are still the same function duplicated in two binaries. The *helper* they shared
  is now one — `proto.SafeText` — but the summarisers themselves are not, and unifying them touches the guest binary.
- `llms-full.txt` is now **460,521 bytes, ~119,659 tokens** — still gendocs's own character estimate, which is what
  P6-17's committed measurement command is for.

## Toolchain
Buildroot **2025.02.17** · Linux **6.12.105** · Firecracker **v1.16.1** · Go **1.27.0**. MCP revision spoken:
**2025-11-25** (legacy era) — the current spec revision is 2026-07-28 and removes the `initialize` handshake
entirely; `docs/mcp-surface.md` made that deferral deliberately and P6-14 states the policy. The HN post is John's
to submit.

Steering needed: no.
