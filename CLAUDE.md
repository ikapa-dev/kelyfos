Read PLAN.html fully at session start; it is the single source of truth and live
status tracker; follow its section 8 protocol.

Verification does not depend on GitHub. `make ci-act` runs the committed
`.github/workflows/ci.yml` checks job in Docker (act) against a clean clone
of HEAD; `limactl shell kelyfos-dev -- dev/ci-local.sh --boot` covers the
microVM half. Run `make ci-act` green before merging to main, and cite its
summary as the evidence whenever no hosted run exists for the commit.
