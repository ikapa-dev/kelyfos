#!/usr/bin/env bash
# Run the `checks` job of .github/workflows/ci.yml here, step for step, and
# print evidence a Progress Log row can cite.
#
# Why this exists. On 2026-08-29 GitHub Actions stopped running for this
# repository at the account level — every workflow active, the repository's own
# Actions setting enabled, and a dispatch answered "Actions has been disabled
# for this user". PLAN.html §8 rule 8 says a clean tree is not a green build,
# and it is right; but with no pipeline at all the choice is between evidence
# that is weaker than CI and no evidence, and "I ran the checks by hand once"
# is the weakest shape that evidence can take. This script is the other shape:
# the workflow's own commands, in the workflow's own order, under the
# workflow's own step names, run by one command whose output is pasted whole.
# When Actions returns and runs the real job on the same commit, the two
# results can be compared line by line, which is what makes the local one
# worth trusting in the meantime.
#
# What is verbatim and what is not. Every `run:` block of the `checks` job is
# copied as written. Three things cannot be: the runner's `apt-get install
# e2fsprogs` becomes a check that mke2fs and debugfs are already here (the
# hostile-corpus job treats their absence as a failure, and so does this); the
# DCO range, which the workflow takes from the push event, is taken from
# `origin/main..HEAD` — the commits a push would add — or from the first
# argument; and the `keep any crashing input` upload becomes a listing, because
# a crasher written to testdata/fuzz/ on this machine is already kept. Unlike
# the runner, which stops at the first failing step, this runs every step and
# reports all of them, so one run says everything that is wrong rather than the
# first thing.
#
# What it does not reproduce. The `build` job (the Buildroot image) and the
# `boot` job (a real x86_64 microVM under KVM, the host seccomp filter read
# back) need a runner this laptop is not. `--boot` runs the nearest thing this
# machine has — `make test-integration`, which boots a real microVM on the
# architecture it has, and the aarch64 half of dev/accept-seccomp.sh — and
# says, in the summary, that it is a stand-in and not the job.
#
# Drift. The `checks` job is the specification and this file is a copy of it,
# so the copy pins a digest of the job's text and refuses to run when the two
# disagree: a step added to the workflow and not here would otherwise pass
# locally by never running, which is the failure mode of every hand-kept list
# this project has retired. Re-align the steps, then update CHECKS_SHA256.
#
# Usage: dev/ci-local.sh [dco-base] [--boot]
#   dev/ci-local.sh                 the checks job, DCO over origin/main..HEAD
#   dev/ci-local.sh b55103f         the checks job, DCO over b55103f..HEAD
#   dev/ci-local.sh --boot          also the boot stand-in (adds ~15 minutes)
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(uname -s)" != "Linux" ]; then
  echo "This reproduces a Linux runner and must run on Linux."
  echo "On macOS use the Lima layer:"
  echo "    limactl shell kelyfos-dev -- dev/ci-local.sh $*"
  exit 1
fi

# The digest of the `checks` job as this file last copied it. See "Drift" above.
CHECKS_SHA256=82823c06a81f3533519af950c8077f0cbe141a103408313cf42d964fee31a5ce

boot=0
dco_base=""
for arg in "$@"; do
  case "$arg" in
    --boot) boot=1 ;;
    -h|--help) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) dco_base="$arg" ;;
  esac
done

actual="$(sed -n '/^  checks:/,/^  build:/p' .github/workflows/ci.yml | sed '$d' | sha256sum | cut -d' ' -f1)"
if [ "$actual" != "$CHECKS_SHA256" ]; then
  echo "the checks job in .github/workflows/ci.yml has changed since dev/ci-local.sh copied it:"
  echo "  pinned  $CHECKS_SHA256"
  echo "  current $actual"
  echo "Re-align this script's steps with the workflow, then set CHECKS_SHA256 to the current value."
  exit 2
fi

head_sha="$(git rev-parse HEAD)"
head_short="$(git rev-parse --short HEAD)"
dirty="$(git status --porcelain | wc -l | tr -d ' ')"

names=()
results=()
seconds=()

# step <name> <command...>: run one step under the workflow's own name, keep
# going whatever it returns, and remember the verdict for the summary.
step() {
  local name="$1"; shift
  echo
  echo "==> $name"
  local t0=$SECONDS
  local rc=0
  "$@" || rc=$?
  local dt=$((SECONDS - t0))
  names+=("$name")
  seconds+=("$dt")
  if [ "$rc" -eq 0 ]; then
    results+=("pass")
    echo "    pass  (${dt}s)"
  else
    results+=("FAIL")
    echo "    FAIL  exit $rc  (${dt}s)"
  fi
}

# ---- the checks job, in order -------------------------------------------

step_gofmt() {
  unformatted="$(gofmt -l . || true)"
  if [ -n "$unformatted" ]; then
    echo "these files are not gofmt-clean:"; echo "$unformatted"; return 1
  fi
}

step_vet() { go vet ./...; }

# internal/vsock's two end-to-end F3 fixtures need a vsock transport. The
# workflow modprobes it; here it is loaded the same way, and a machine that
# cannot is left to the fixtures' own skip (P7-17/C).
step_vsock() {
  if [ -d /sys/module/vsock_loopback ]; then
    echo "vsock_loopback already loaded"
    return 0
  fi
  sudo -n modprobe vsock_loopback 2>/dev/null || true
  if [ -d /sys/module/vsock_loopback ]; then
    echo "vsock_loopback loaded"
  else
    echo "vsock_loopback is not available here; internal/vsock's two end-to-end F3 fixtures will skip"
  fi
}

step_unit() { go test -count=1 ./...; }

step_fuzz() { make fuzz FUZZTIME=10s; }

# The runner uploads **/testdata/fuzz/** on failure; here the files stay where
# the toolchain wrote them, so the equivalent is to say which ones are new.
step_crashers() {
  local new
  new="$(git status --porcelain -- '**/testdata/fuzz/**' 2>/dev/null | sed 's/^/    /')"
  if [ -n "$new" ]; then
    echo "crashing inputs written by the fuzz step (kept in place, not committed):"
    echo "$new"
  else
    echo "no new crashing input"
  fi
}

step_hostile() {
  for tool in mke2fs debugfs; do
    command -v "$tool" >/dev/null || { echo "$tool is not installed; KELYFOS_HOSTILE=required makes that a failure, not a skip"; return 1; }
  done
  KELYFOS_HOSTILE=required go test -count=1 -run 'TestHostile|TestGuestChosen|TestTheWorkspaceRoot' ./...
}

step_plan() { python3 tools/check-plan.py; }

step_changelog() { python3 tools/changelog.py --check; }

step_dco() {
  local base="$dco_base"
  if [ -z "$base" ]; then
    if git rev-parse --quiet --verify origin/main >/dev/null 2>&1; then
      base="$(git rev-parse origin/main)"
      echo "range: origin/main..HEAD (the commits a push would add)"
    else
      echo "no origin/main in this clone and no base given; nothing to compare, as the workflow would say"
      return 0
    fi
  fi
  bash tools/check-dco.sh "$base" "$head_sha"
}

step_docs() {
  make docs || return 1
  generated="docs/reference llms.txt llms-full.txt"
  if ! git diff --quiet -- $generated || \
     [ -n "$(git status --porcelain -- $generated)" ]; then
    echo
    echo "the generated documentation disagrees with the source:"
    git --no-pager diff -- $generated
    git status --porcelain -- $generated
    echo
    echo "Run 'make docs' and commit the result."
    return 1
  fi
  echo "the reference, llms.txt and llms-full.txt all match"
}

step_cookbook() {
  local out r
  out="$(mktemp -d)"
  go run ./tools/cookbook -in docs/cookbook.md -out "$out" || return 1
  for r in "$out"/*.sh; do
    bash -n "$r" || { echo "$(basename "$r"): shell syntax error"; return 1; }
    echo "  ok  $(basename "$r" .sh)"
  done
}

# ---- the boot stand-in ---------------------------------------------------

step_boot() { make test-integration; }

step_seccomp() { bash dev/accept-seccomp.sh; }

# ---- run -----------------------------------------------------------------

echo "dev/ci-local.sh — the checks job of ci.yml, reproduced locally"
echo "head    $head_sha"
echo "date    $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host    $(uname -srm), $(go version | cut -d' ' -f3)"
[ "$dirty" -eq 0 ] || echo "note    working tree has $dirty uncommitted change(s); the head above is not what ran"

step "gofmt"                                                   step_gofmt
step "go vet"                                                  step_vet
step "the vsock loopback transport, so the F3 fixtures run"    step_vsock
step "unit tests"                                              step_unit
step "fuzz, briefly"                                           step_fuzz
step "keep any crashing input"                                 step_crashers
step "The boundary holds against what the guest can write"    step_hostile
step "the plan is still coherent"                              step_plan
step "every released tag has its notes"                        step_changelog
step "new commits carry a DCO sign-off"                        step_dco
step "The generated reference still matches the source"       step_docs
step "Every cookbook recipe extracts and parses"               step_cookbook

if [ "$boot" -eq 1 ]; then
  step "[boot stand-in] make test-integration on $(uname -m)"  step_boot
  step "[boot stand-in] dev/accept-seccomp.sh on $(uname -m)"  step_seccomp
fi

# ---- summary, in the shape a Progress Log row cites ----------------------

echo
echo "---- summary: ci.yml checks job, local, head $head_short ----"
failed=0
for i in "${!names[@]}"; do
  printf '  %-4s  %4ss  %s\n' "${results[$i]}" "${seconds[$i]}" "${names[$i]}"
  [ "${results[$i]}" = "pass" ] || failed=$((failed + 1))
done
if [ "$boot" -eq 0 ]; then
  echo "  ----   not run: build job (Buildroot image), boot job (x86_64 microVM under KVM) — pass --boot for the nearest local stand-in"
else
  echo "  ----   build job not reproduced (Buildroot image); boot job represented by its $(uname -m) stand-in, not the x86_64 run"
fi
if [ "$failed" -eq 0 ]; then
  echo "  all ${#names[@]} steps passed on $head_short — local evidence, not a green pipeline (PLAN.html §8 rule 8)"
  exit 0
fi
echo "  $failed of ${#names[@]} steps FAILED on $head_short"
exit 1
