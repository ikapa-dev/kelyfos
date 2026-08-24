# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **53/74**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35): every row now has a
  verdict and none will be ticked there. **Phase 6 open — "v1.0, the promise", 21 tasks**, drafted spec-first at P6-0.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-6 done, both halves.** The hash preimage landed first (commit `95e139e`): the digest is recomputed from the
bytes as written, so a chain from a newer build no longer comes back as `event N has been modified`. This commit is
the other half — **the export made verifiable by its reader**.

The record the page was rendered from now travels *inside* it: base64 of `events.jsonl`, exactly as the host wrote
it, in a `<pre id="kelyfos-chain">` at the foot of the page. The chain head is printed as text.
`kelyfos verify <report.html>` re-runs the same walk the recorder already implements — offline, no key, no network,
no trust root of ours — and takes a raw `events.jsonl` too, so sender and receiver check the same thing with the
same command. The green tick the file used to render about itself is gone; what replaced it is a statement of what
the file carries and the command somebody else runs. **The failure case is kept**, because the asymmetry is the
point: a file certifying itself is worth nothing, a file reporting a problem with itself is worth reading.

**The limit is stated before the capability** — on the page, in the command's output, and in the threat model.
Verification covers the *record*, not the page's rendering of it: a page whose visible text was edited afterwards
still carries an intact record. `kelyfos verify --replay` prints the record's own account so the two can be
compared. Nothing keyless closes that gap and the product says so rather than implying otherwise.

**Two live defects, both found by an adversarial review of the design commissioned before the code.**
A chain with **no digests at all verified** — `"hash":""` on every line, the cheapest forgery there is, because the
digest of a line with an empty hash was defined as empty and matched it. Harmless while the file being checked was
one this machine wrote; `kelyfos verify` is what made a stranger's file the input. And **`html/template` escapes
`+`**, which is an ordinary base64 character — the island was shipping corrupted for any record whose encoding
contained one, and the reader would have been told an untouched record had been modified. That is precisely the
false alarm this task's first half removed, reintroduced at the export. Both are fixed, both have tests that fail
without the fix.

**Next: P6-7** — signed exports, `--sign-key`, ed25519 from the standard library, a key the reader holds. It is a
promotion of something that already works rather than a substitute for it, which is why it was sequenced second.

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
- **The rendering gap is open by design and permanent.** `kelyfos verify` covers the record a report carries, not
  the page's drawing of it. Cross-checking the numbers the page prints was considered and declined: it couples the
  verifier to the template, catches only an edit nobody would bother to make, and a partly-checked page invites a
  reader to treat the rest as checked — the badge's failure wearing a hex string.
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
