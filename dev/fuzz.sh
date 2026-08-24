#!/usr/bin/env bash
# Run every fuzz target in the repository for a while (P6-3).
#
# `go test -fuzz` takes exactly one target in exactly one package per
# invocation: there is no `-fuzz ./...`. So something has to enumerate the
# targets, and the obvious something — a list in a workflow file — is a list
# that goes out of date silently. A target added without a matching line in CI
# simply never runs, and nothing says so. That is the same shape as the
# generated-reference drift this project already guards against, and the same
# shape as the fuzz-target inventory a guard test would have been written to
# check.
#
# This does not have a list. It asks the toolchain what targets exist, which
# makes the drift impossible rather than detectable: `go test -list` reports
# fuzz targets alongside tests, so a new FuzzXxx is picked up by the next run
# with nothing to remember.
#
# The one failure a discovering runner still has is finding nothing at all — a
# broken discovery would run zero targets and exit cleanly, which looks exactly
# like success. So the count is checked at the end and printed either way.
#
# Usage: dev/fuzz.sh [fuzztime]      e.g. dev/fuzz.sh 10s   dev/fuzz.sh 3m
set -euo pipefail

fuzztime="${1:-${FUZZTIME:-10s}}"

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ran=0
failed=0
for pkg in $(go list ./...); do
  # `go test -list` builds the package and prints matching names. A package
  # with no test files prints nothing, which is why this is filtered rather
  # than trusted.
  targets="$(go test -list='^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true)"
  [ -n "$targets" ] || continue
  for target in $targets; do
    echo "==> $pkg $target ($fuzztime)"
    # -run='^$' so the package's ordinary tests do not run once per target.
    if ! go test -run='^$' -fuzz="^${target}\$" -fuzztime="$fuzztime" "$pkg"; then
      failed=$((failed + 1))
    fi
    ran=$((ran + 1))
  done
done

echo
if [ "$ran" -eq 0 ]; then
  echo "no fuzz targets were found — the discovery is broken, not the code" >&2
  exit 1
fi

if [ "$failed" -gt 0 ]; then
  echo "$failed of $ran fuzz targets failed."
  echo "A failing input is written to the package's testdata/fuzz/<Target>/ and is"
  echo "a permanent regression seed once committed — commit it with the fix."
  exit 1
fi

echo "$ran fuzz targets, $fuzztime each, no failures."
