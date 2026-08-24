# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **47/74**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35): every row now has a
  verdict and none will be ticked there. **Phase 6 open — "v1.0, the promise", 21 tasks**, drafted spec-first at P6-0.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-5 done.** Echo suppression — a bound credential that comes *back* in a response is replaced before the guest
sees it. That is the one case construction cannot reach: KelyfOS keeps the value out of the guest by putting it in
only on the way out, so a value returning is a direction it never sent.

It is named for what it is. Exact matching on the bound values, nothing else. D37 declined general credential
detection outright rather than deferring it, because pattern-matching a byte stream the agent is about to parse
means a false positive silently corrupting a tarball, undiagnosable from inside the guest.

**Three limits, documented ahead of the capability**: the tunnelled majority is ciphertext and can never be
covered; a compressed body is not covered, because the terminated transport deliberately does not decompress; and a
value under eight bytes is not scrubbed. The replacement is length-preserving, which is not cosmetic — a body whose
written length disagreed with its `Content-Length` would poison every later exchange on a keep-alive connection.

Two things the work turned up. The **fuzzer refuted my invariant rather than the code** — a value made largely of
the filler byte can be re-created by the act of replacing it — so the property is now stated against the input's
positions. And the first thing echo suppression caught was **this project's own test**, whose upstream reflected
the credential back as the response body.

**Next: P6-6** — the session export made verifiable by its reader, carrying the hash-preimage fix P6-4 measured.

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
- **`docs/events.md` §3 says "adding a field is not breaking". It is false**, measured: a chain written by a build
  with one more `Event` field makes an older build report `event N has been modified`. The fix — hashing a
  canonical form rather than the marshalled struct — is now part of P6-6 and must land before v1.0 freezes.
- **Every `snapshot restore` session recorded before this phase is missing its egress events entirely.** Belongs in
  the upgrade guide, P6-16.
- Pre-existing and unfixed: `args = ["server.js", "--x=a,b"]` in a `[[plugin]]` block fails to load, because the
  toml array parser splits on the comma before parsing quotes. Same cause as the cut method syntax.
- `kelyfos snapshot restore` never reads `kelyfos.toml` at all — no ceilings, no allow, no secrets from the file.
  Defensible, undocumented, and a question P6-14's promise has to answer.
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
- The two MCP argument summarisers are still the same function duplicated in two binaries (P6-1 found one
  redacting a `data` key the other did not). The *helper* they shared is now one — `proto.SafeText` — but the
  summarisers themselves are not, and unifying them touches the guest binary.
- `llms-full.txt` is now **444,241 bytes, ~115k tokens** (estimated, not measured — a committed measurement
  command is P6-17).

## Toolchain
Buildroot **2025.02.17** · Linux **6.12.105** · Firecracker **v1.16.1** · Go **1.27.0**. MCP revision spoken:
**2025-11-25** (legacy era) — the current spec revision is 2026-07-28 and removes the `initialize` handshake
entirely; `docs/mcp-surface.md` made that deferral deliberately and P6-14 states the policy. The HN post is John's
to submit.

Steering needed: no.
