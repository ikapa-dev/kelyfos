# KelyfOS — session status

Updated 2026-08-25 · synced with origin/main · **v1.0 tagged** · CI green on main · **Phase 6 CLOSED**

## Plans
- PLAN.html — **78/85**. All Phase 6 tasks done. Phases 0–3 and 5 done. Phase 4 dispositioned and parked (D35). **Phase 6 closed —
  "v1.0, the promise", 32 tasks**: an external security audit arrived mid-phase and added seven (D45), the
  documentation audit added one more (D49), and the owner's rulings added three (D54, D55, D56).
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The bar stops at 78/85 and is meant to.** The seven open boxes are Phase 4's permanent record rows (D34) —
  a record of what was dispositioned, not work left undone.

## Now

**Phase 6 is closed and v1.0 is tagged.** 32 tasks, 20 decisions recorded this phase, CI green.

**The external security audit is answered in full.** Twenty-four findings read against current source before
anything was touched, across three instalments. Twelve fixed in the long tail, the rest already closed by the
boundary work or decided with a reason. **Not one was fixed from its description alone** — and that mattered:
every finding in the last instalment was inaccurate about something, usually the part a fix would be built on.
M-1 named the wrong oracle, M-6 joined two independent defects as cause and effect, L-3 named the wrong
casualty, L-4's proposed fix would have left a second instance untouched.

**The documentation audit corrected 174 claims across 21 documents**, and a second adversarial pass caught
**fourteen corrections that were themselves newly false** — each a true fix given a false scope. It also found
eighteen defects in the code, where E3-0 found four.

**Three defects were found by running rather than reading**, and they are the argument for the suites:
- `kelyfos pause` could not stop a microVM on **x86_64** — the guest called POWER_OFF, and Firecracker
  virtualises no power management there. Every machine here is arm64, where PSCI hides it.
- **Resuming a paused session emptied the project directory** and printed "workspace written back". The
  agent's work was in neither the directory nor the backup.
- Every exported report had been **owner-only since P6-6**, because the atomic-export fix inherited
  `os.CreateTemp`'s 0600.

**The docs-only exam found a trust defect in v1.0's own new work**: the report printed a signing-key
fingerprint it told the reader to act on, and it was the one value `kelyfos verify` did not check.

**Two release candidates before the tag.** rc1 failed at the SBOM attestation — `actions/attest` needs a
`serialNumber` and Buildroot emits none, so every SBOM this project ever produced would have been refused. The
step had never run, because no release had ever been built by a workflow. rc2 is green: 12 assets, drafted.

**Measured for v1.0**, on the bare-KVM reference: boot **134 ms** median (p95 143), restore **48 ms** (p95 53),
both targets met with room. Five agents **343–543 ms** cold — printed as a range because one sample on a shared
runner varied by 58% between two runs. 14 acceptance suites, 263 checks; 15 cookbook recipes; 1,542 historical
chains all verify under the v1.0 verifier.

## Blocked / needs John
- **The audit's text for M-1, M-4, M-6, M-7, M-8, L-1 through L-7 and D-1.** Twelve findings are known here only
  as identifiers. P6-23 (triage) and P6-27 (the long tail) both wait on it. Nothing in the v1.0 gate or the
  blocking set is among them — those are triaged whole (D46, D47). Three of the eleven findings that *were*
  triaged did not say what they were reported to say, so the remaining twelve are worth reading rather than
  assuming.
- **All owner actions are settled as of 2026-08-25.** Nothing on this list blocks the phase any more; what is
  left is the work each ruling created.
  - **Private vulnerability reporting: ENABLED.** `SECURITY.md`'s workaround paragraph is retired rather than
    deleted, so a reporter following the old advice learns it was superseded.
  - **Immutable releases: ON** (D53). D39's rule is unchanged: it attests *publication*, never build
    provenance, and the two never share a sentence.
  - **Dependabot security updates: ON** (D54), as its own consent — it opens bot-authored pull requests rather
    than reporting, which is a different agreement. **P6-30** carries the work, and the rule that matters is
    that a bot branch must not reach the KVM workflows.
  - **DCO: gate new commits** (D56). History is not rewritten and the requirement is not dropped;
    `CONTRIBUTING.md` gains one line saying pre-v1.0 history predates enforcement. **P6-29** carries it.
  - **macOS: ship raw for v1.0** (D55). No Apple identity today, so the darwin binaries are unsigned and
    Gatekeeper quarantines them; the documentation states that and the clearing step plainly rather than
    letting a first-time user meet the dialog unwarned. **P6-31** carries it. Signing and notarization are
    post-1.0 the moment an identity exists.
- P4-4, P4-5 **[BLOCKED]**, re-verified 2026-08-24: 0 stars, 0 forks, 0 issues, discussions off. Now dated rather
  than eternal — revisit 30 days after the v1.0 launch, since this phase's own exit is the act most likely to
  change those facts.

## Debts carried into Phase 6
- **Cleared this stretch:** the `0.1.0-dev` guest os-release (P6-9, generated and verified in a built image);
  `SHA256SUMS` appended-to-and-never-truncated (P6-8); the CI cache key that made every release build run cold
  (P6-8); `docs/events.md` §3's "adding a field is not breaking", true now and saying it was false until v1.0.
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
- The five-agent pair is a **range, not a number**: re-measured twice on one commit it gave **343 ms and 543 ms
  cold, 285 ms and 384 ms forked** on `demo-team`'s graph (the old published 412/286 sits inside that spread), and
  `prove-team`'s CPU-capped run gave 831–923 ms cold. One cold sample on a shared CI machine varies by 58% of its
  own value, so the README prints the range. And the macOS quickstart is not one number — **10 s is KelyfOS's own
  part**, the Linux layer was 28 s warm and 138 s cold and that part is Lima's.
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
- `llms-full.txt` is now **544,314 bytes, ~141,425 tokens** — still gendocs's own character estimate, which is what
  P6-17's committed measurement command is for.
- **`docs/media/demo.cast` shows `supervisor 0.2.0-p2`**, a version string P6-1 deleted from the code. The demo
  GIF is the first thing on the README. Fixing it means re-recording on a KVM machine — hand-editing a recording
  would turn evidence into a drawing of evidence — so it belongs with P6-18 or P6-20, whichever reaches hardware
  first.

## Toolchain
Buildroot **2025.02.17** · Linux **6.12.105** · Firecracker **v1.16.1** · Go **1.27.0**. MCP revision spoken:
**2025-11-25** (legacy era) — the current spec revision is 2026-07-28 and removes the `initialize` handshake
entirely; `docs/mcp-surface.md` made that deferral deliberately and P6-14 states the policy. The HN post is John's
to submit.

Steering needed: no.
