Read CONTRIBUTING.md before changing anything — "How a change is verified" is
the protocol every change follows here. docs/roadmap.md is what was built and
the task IDs the source cites; docs/decisions.md and docs/decisions-features.md
are why, cited from comments as D<n> and F-D<n>.

The maintainer's working tracker (PLAN.html) is deliberately not in this
repository: it is a process document. Where it is present locally it governs
task order and carries the progress log.

Verification does not depend on GitHub. `make ci-act` runs the committed
`.github/workflows/ci.yml` checks job in Docker (act) against a clean clone
of HEAD; `limactl shell kelyfos-dev -- dev/ci-local.sh --boot` covers the
microVM half. Run `make ci-act` green before merging to main, and cite its
summary as the evidence whenever no hosted run exists for the commit.

UNTIL GITHUB ACTIONS IS BACK (account-level outage since 2026-08-25; D73, D77):
- At session start, confirm it is still out: `gh workflow run ci.yml --ref main`
  answering "HTTP 422: Actions has been disabled for this user" means out. A
  head of main with no hosted run is red, not unknown (section 8 rule 8).
- `make ci-act` is the local evidence of record for the checks job — evidence,
  not the pipeline; the pipeline is GitHub's and it is down. Run it on the
  exact commit you merge — not on a parent, not on a dirty tree — and paste
  its summary whole into the Progress Log row. The one exception is the
  commit that carries that row, which cannot have been run against because
  it does not exist yet: cite the run on the head at the time and say that
  the only commit after it is the row itself. It refuses a second concurrent
  run on this machine; wait rather than work around it.
- Any change under supervisor/, image/ or internal/sandbox additionally needs
  `limactl shell kelyfos-dev -- dev/ci-local.sh --boot` and the relevant
  dev/accept-*.sh, which kill every Firecracker on the box — never while a
  microVM someone else started is running.
- Write "local evidence", never "green pipeline". Do not tick P7-17, do not
  tag, and do not close anything whose condition is a hosted run.
- Push every merge to origin the same day; the pipeline being down is not a
  reason for main to exist only on one laptop.
- When Actions returns: `gh workflow run ci.yml --ref main` and the same for
  security.yml on the current head, compare against the act summaries in
  the Progress Log, and delete this block in the commit that records the
  first green.
