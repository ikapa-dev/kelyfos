# KelyfOS — session status

Updated 2026-08-24 · synced with origin/main · **v0.9 released** · CI green on main · **Phase 6 open**

## Plans
- PLAN.html — **47/74**. Phases 0–3 and 5 done. **Phase 4 dispositioned and parked** (D35): every row now has a
  verdict and none will be ticked there. **Phase 6 open — "v1.0, the promise", 21 tasks**, drafted spec-first at P6-0.
- PLAN-FEATURES.html — **COMPLETE and closed.** 42/42, five epics, v0.4–v0.8 released.
- **The overall bar will not reach 100% and is not meant to.** Seven of the denominator's boxes are Phase 4's
  permanent record rows. A denominator adjusted to flatter the numerator is the same defect as a ticked box.

## Now
**P6-3 done. Sixteen fuzz targets, and seven real defects out of writing them** — which is the part worth reading.

The boundary is declared first (D43), because "every untrusted-input parser" has no completion criterion without
one: **hostile** is anything a guest wrote, anything the network returned, and anything arriving with a cloned
repo or a download (`kelyfos.toml` is *meant* to be committed and cloned). **Not hostile** is state KelyfOS wrote
to its own cache — a corrupt state file is a bug, not an adversary, and calling it one would make the word mean
nothing.

Four of the seven findings came from asserting a *property* rather than waiting for a panic. Two were silent
failures, the worse kind: a credential bound to `github.com.` — the fully-qualified spelling — parsed cleanly and
matched nothing, so requests went out unauthenticated with a 401 from somewhere else as the only symptom; and a
`mem` value large enough to overflow int64 became a **negative** ceiling that every flag was then compared
against. The credential bug had a cause worth naming: one normalisation expression in four copies with three
behaviours, and the copy in `containsDomain` carried a comment promising it matched the proxy. Three findings were
the same class three times — agent-chosen text reaching a rendered transcript line (an argument key, a value, an
OOM victim's process name). Two were the proxy accepting a port of 99999 and a host of `/`.

The runner **discovers** its targets rather than listing them, so the drift a guard test would have detected cannot
happen. Coverage is stated as coverage, not totality — `docs/threat-model.md` names which parsers are fuzzed and
which are left out with the reason. Sixteen is not "every parser", and this phase opened by deleting claims of that
shape.

**Next: P6-4** — the credential window narrowed as far as the architecture allows.

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
- **The two MCP argument summarisers are the same function in two binaries and have now diverged twice** — P6-1
  found one redacting a `data` key the other did not, P6-3 found the control-character hole in both. Unifying them
  touches the guest binary; recorded as a debt rather than folded into a fuzzing task.
- `llms-full.txt` is now **444,241 bytes, ~115k tokens** (estimated, not measured — a committed measurement
  command is P6-17).

## Toolchain
Buildroot **2025.02.17** · Linux **6.12.105** · Firecracker **v1.16.1** · Go **1.27.0**. MCP revision spoken:
**2025-11-25** (legacy era) — the current spec revision is 2026-07-28 and removes the `initialize` handshake
entirely; `docs/mcp-surface.md` made that deferral deliberately and P6-14 states the policy. The HN post is John's
to submit.

Steering needed: no.
