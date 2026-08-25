<!--
Thanks for this. Three things are worth knowing before the checklist, because
they are where pull requests to this project actually come unstuck.

1. The non-goals in PLAN.html §2 are hard boundaries: no orchestrator, no control
   plane, no hosted service, no web dashboard, no new kernel, no VMM. A pull
   request that crosses one is declined however good the code is. This is not a
   judgement about the work.

2. Every commit needs a `Signed-off-by` line (`git commit -s`). CONTRIBUTING.md
   has the DCO and why it is a sign-off rather than a CLA.

3. Claims in this repository are measured or they are not made. A number in a
   comment, a document or a commit message needs the command that produced it.
-->

## What this changes, and why

<!-- The why matters more than the what; the diff already says the what. -->

## How you know it works

<!--
Not "tested locally". What you ran and what it said. If the change is on a path
that needs a real microVM, say so and say what you could and could not run — an
honest gap is fine and a vague claim is not.
-->

---

- [ ] `make test` passes, and the tree is `gofmt` clean
- [ ] A user-visible change has a `CHANGELOG.md` entry under `## Unreleased`
- [ ] A breaking change has a section in `docs/upgrading.md` saying what to do
- [ ] A changed flag, key, tool, event or exit code: `make docs` re-run and the
      regenerated reference committed
- [ ] A change of approach, library or scope: recorded in `PLAN.html`'s decision
      log with its rationale, so the next reader learns why and not just what
- [ ] Commits carry `Signed-off-by` and reference the task ID they belong to
