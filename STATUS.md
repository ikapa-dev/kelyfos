# KelyfOS — session status

Updated 2026-08-25 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **69/82**. Phases 0–3 and 5 done. Phase 4 dispositioned and parked (D35). **Phase 6 open —
  "v1.0, the promise", 29 tasks**: an external security audit arrived mid-phase and added seven (D45), and the documentation audit added one more (D49).
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows.

## Now
**The audit's v1.0-blocking set is closed** — the boundary group (P6-24), the exhaustion clamps (P6-25), and the
two claims the code did not keep (P6-26). The hostile ledger is **one line**, and that line is a recorded
decision: the shim is unauthenticated by default on purpose, and a token can now be required.

**Nine more tasks since, in plan order.** P6-7 signed exports, with a key the reader anchors and a *vocabulary*
rather than a badge. P6-8 the release built by CI, sums written from scratch and checked both ways. P6-9
determinism configured and then **measured** — two full builds from nothing produce byte-identical artifacts,
which is more than D38 expected. P6-10 an SBOM covering the seam Buildroot cannot see. P6-11 provenance
attestations, with the immutable-release claim refused in the same breath. P6-12 the CLI on macOS, with `doctor`
owning the Lima layer. P6-13 `kelyfos connect`, six client writers and a real MCP handshake. P6-14 the
compatibility promise.

**Things found by doing rather than by reading**, all fixed:
- A **chain with no digests verified** — the cheapest forgery there is.
- **`html/template` escapes `+`**, so the embedded record was silently corrupt for some sessions.
- A **failed export truncated the report already at that path** to zero bytes.
- A guest's refusal **wrote ANSI escapes on the operator's terminal**.
- An agent name **granted itself a spawn budget** through the kernel command line.
- Stripping group-write **rewrote every `0664` file** in a umask-002 user's project — caught by the acceptance
  suite, which no fixture would have.
- **`main` went red once**: P6-9 emptied the flavor overlay directories and git does not track empty ones, so a
  clean checkout had no overlay for rsync. It passed locally. CI's fresh checkout is the whole reason §8 rule 8
  says to read the pipeline and not only the tree.
- **The record's field order was frozen ABI that nothing checked** — reordering it would have made every chain
  KelyfOS has ever written report as modified.

**Live-checking earned its keep twice.** `actions/attest-build-provenance@v1` is two majors and one permission out
of date; the plan's own wording (`actions/attest`) was right and the obvious guess was not. And the Buildroot
CycloneDX generator does exist — as `utils/generate-cyclonedx`, invisible to a grep of the Makefile.

**P6-15 done — the documentation audit, re-run whole.** 21 documents read against the code that implements
them, 202 candidate findings, 28 refuted by a second pass, **174 confirmed** and 157 corrected. The record is
`dev/docs-audit-2026-08-25.md`, committed *before* the corrections so what was wrong survives the fixing of it.

**The correction pass needed its own adversary, and that is the finding.** Every corrected document was re-read
against the source rather than against the brief, and **fourteen corrections were themselves newly false** — each
one a true fix given a false scope ("the three commands run through sudo" when a fourth is; "delivered sixty-four
times over" when sixty-four is a capacity, not a count). A vague overclaim replaced by a precise falsehood is
worse than what it replaced, because a reader acts on the precise one. Two of the fourteen re-introduced the
attestation claim this same task had just removed from the README; chasing them found a third copy the audit had
never flagged.

**Three of the worst findings were claims written earlier in this session** — the README's provenance
attestation, its "built by release.yml" downloads, and "guest-chosen modes do not survive", which stopped being
true the moment P6-24 narrowed `safeMode` and the sentence was not narrowed with it. Eleven hours from claim to
contradiction, not a release cycle.

**Eighteen code defects came out of it**, where E3-0 found four. Three fixed here (two stale `reason` lists in
`internal/recorder/schema.go`, which drive the generated reference, and a release-workflow `rm` that let two jobs
upload the same macOS filenames); **fifteen routed to P6-28** by D49 rather than folded into a documentation
commit. The sharpest: `kelyfos shell` reports `exited 0` when the supervisor died mid-session, contradicting both
`docs/protocol.md` §5.7 and `proto.ShellExit`'s own doc comment.

**P6-16 done — the documents a 1.0 is expected to have.** `CHANGELOG.md` v0.0 through the unreleased v1.0,
`docs/upgrading.md`, a CONTRIBUTING refresh, and issue/PR templates.

**The question that task existed to settle is settled (D50): the changelog is the source, not a mirror.** The
release workflow stopped writing its own notes and now cuts them from the file — and `tools/changelog.py` exits
non-zero when a tag has no section, so a release with no notes fails instead of publishing. CI runs the same
check on every commit, which moves the failure from publish time to push time. The eight existing GitHub release
bodies are not backfilled: they are what was published, and rewriting them would be editing the past.

**P6-17 done — the generated set, and a defect in this phase's own measurement tool.** The reference,
`llms.txt` and `llms-full.txt` are current: **544,314 bytes, 141,425 tokens** by `make tokens`, the committed
invocation. The tool's own comment claimed its divisor was "the same constant `tools/gendocs` prints with, so the
two cannot disagree" — they were two independent `const charsPerToken = 3.83` in two packages, holding the same
value by coincidence. There is one now, in `internal/docsize`, with the ratio's provenance beside it and a test
that fails if it is repinned without re-measuring. The refactor leaves the generated set byte-identical.

**Next: P6-18** — the bars and every suite. **It needs the bare-KVM reference (D15)** and **P6-19 needs a fresh
session with no source tree** — both are environment-bound rather than work-bound.

## Blocked / needs John
- **The audit's text for M-1, M-4, M-6, M-7, M-8, L-1 through L-7 and D-1.** Twelve findings are known here only
  as identifiers. P6-23 (triage) and P6-27 (the long tail) both wait on it. Nothing in the v1.0 gate or the
  blocking set is among them — those are triaged whole (D46, D47). Three of the eleven findings that *were*
  triaged did not say what they were reported to say, so the remaining twelve are worth reading rather than
  assuming.
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
