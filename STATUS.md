# KelyfOS — session status

Updated 2026-08-25 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **55/81**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35). **Phase 6 open —
  "v1.0, the promise", now 28 tasks**: an external security audit arrived mid-phase and added seven (D45).
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-22 done: the hostile corpus is complete.** Nine fixture groups across five packages, twenty-one boundary
cases recorded broken, and a CI job named for the question it asks. Every case drives the real code with no VM —
a crafted ext4 image, a Unix socket speaking the vsock handshake, an `httptest` handler, a broker frame decoded
by the product's own reader. Until this task **`Broker.Serve` had no test behind it at all**, which is the entry
point an agent reaches.

**The ledger is the mechanism worth remembering.** The corpus must fail before it passes, but a red `main` until
P6-24 would make §8 rule 8 stop meaning anything. So `testdata/hostile/known-broken.txt` records the failures and
the check is symmetric: an unlisted failure is a new break on the commit that caused it, and a listed case that
starts holding must take its own line off in the commit that fixed it. **It earned itself four times** — it
refused an over-listing, caught a case keyed by a name containing a NUL, panicked when a fixture that must
`chdir` moved the ledger out from under itself, and removed `exec/flood-with-bytes` because that one holds.

**Two fixtures do not test the finding that prompted them**, and say so in their own files. M-9 as worded was
fixed before the audit was read; what is live is that the ceiling counts *bytes*, so frames carrying none make
`Exec` never return, and the `timeout` in its signature is a number mailed to the untrusted party rather than a
deadline on the socket. And building the OpTrust stub found something the audit did not: **a guest's refusal
reaches the operator's terminal with its control bytes intact** — a guest answering `\x1b[1A\x1b[2K\r` erases
the line the host just printed about it. `proto.SafeText` exists for exactly this and is not applied there.

**Still true from D46, and it contradicts the briefing**: H-6 is *not* partly fixed. `git diff babec8f..HEAD --
shim/` is five lines of audit wiring. Both halves are live.

**Next: P6-23** — the remaining sixteen verdicts. Two corrections in the first seven is a rate worth carrying into
the rest. Then **P6-24**, the gate, which now opens only on green fixtures *and* a full acceptance suite, with the
documentation corrections riding the same commit and the boot/restore bars re-measured if the extraction path
moved.

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
