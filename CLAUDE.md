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
