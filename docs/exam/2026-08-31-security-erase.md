# The security exam — template and first run

*ST-6.3. The repo's E3-5 docs-exam pattern pointed at security: an agent is
given `docs/threat-model.md` and the `kelyfos` binary — no source tree, no
suites, no plan files, no audit — and asked to FALSIFY one claim. The claim
is chosen by the operator, not the agent, so the exam cannot drift toward
whatever is easy to defend. Every failure the agent produces becomes either a
doc fix or a code fix; a claim that survives is recorded as having survived
an attempt, which is different from never having been attacked.*

---

## Template

1. **Pick one claim** from `docs/threat-model.md` or the README's security
   table — one sentence, falsifiable by dynamic probing, ideally one no
   existing suite assertion covers.
2. **Prepare the environment**: the `kelyfos` binary from the commit under
   test, `docs/threat-model.md`, a Linux machine with KVM and the dev image.
   Nothing else. The agent does not get the suites; the suites are what the
   exam is checked against afterwards.
3. **The ask**: "falsify this claim, or report that you could not". The agent
   writes its probes, runs them, and reports: what it tried, what it
   observed, what it concludes.
4. **Adjudicate**: every reported success at falsification is re-run by
   someone who can see the source (the exam's equivalent of the E3-5
   adjudicator). A finding survives adjudication if the probe is reproducible
   and the claim, read precisely, is false. A probe that misses something
   findable is also a result — it means the claim is hard to test, not that
   it is true.
5. **Repair**: a surviving finding becomes a doc fix or a code fix, cited by
   the exam date; a claim that survives is added to
   `docs/security-assertions.md` (ST-6.4's matrix) as machine-checked if a
   suite assertion covers it, and as "survived one attempt" otherwise.

---

## First run — 2026-08-31, the erase path

**Claim** (from `docs/threat-model.md`, the record-erasure section):
erasure removes what was said while the record's chain still verifies —
"keep the record, erase what it said" (cookbook 17).

**Given**: the binary built from the commit under test, the threat model, a
Lima VM with the dev image. Probes were written and run by the exam agent
without sight of the suites or the source.

**The probes, as actually run**:

```
kelyfos run --image dev                          # a session with a payload
kelyfos exec "echo secret-eraseme-token > /tmp/x"  # worth erasing
kelyfos log --session <id> | grep -c <payload>   # 1 — the record holds it
kelyfos sessions erase -reason "..." <id>        # the erasure
kelyfos log --session <id> | grep -c <payload>   # what remains
kelyfos log --session <id> --verify              # the chain after erasure
```

**Observed**:

- The first erase attempt was REFUSED: "has a live run directory and may
  still be running — erasing a chain still being written to would race the
  writer". A protection the claim's own sentence does not mention, found by
  probing: erasure refuses a session whose run is live rather than racing
  its writer. Recorded here because a reader of the cookbook would not
  expect the refusal.
- After the run stopped: `erased <id>: 2 event(s) redacted, 8 events, chain
  intact` — the payload count goes from 1 to 0 and `--verify` reports the
  chain intact on the rewritten record.

**Result**: the claim survived one falsification attempt, and the attempt
produced one documented refinement (the live-session refusal). The
erase-then-verify sequence is the shape `dev/accept-security-record.sh`
could adopt if the erase path ever needs a suite of its own; until then the
claim is recorded here as having survived one attempt, per the template's
step 5.
