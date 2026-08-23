#!/usr/bin/env bash
# KelyfOS — run every recipe in docs/cookbook.md (E3-3).
#
#   bash dev/cookbook.sh              every recipe
#   bash dev/cookbook.sh one-sandbox  just that one
#
# The recipes are the documentation. What runs here is the text a reader copies
# out of the cookbook, extracted rather than transcribed, so a recipe that stops
# working fails the build instead of failing a stranger.
#
# Needs a real machine: KVM, Firecracker, and the dev image. `kelyfos doctor`
# says whether this one qualifies.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COOKBOOK="${COOKBOOK:-$REPO/docs/cookbook.md}"
BIN="${BIN:-$REPO/bin}"
WORK="$(mktemp -d)"
PASSES=0 FAILURES=0
SUMMARY=()

cleanup() {
  pkill -f "$BIN/kelyfos run"  2>/dev/null
  pkill -f "$BIN/kelyfos fork" 2>/dev/null
  pkill -f "$BIN/kelyfos team" 2>/dev/null
  pkill -f "$BIN/kelyfos shim" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1));  SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }

export PATH="$BIN:$PATH"

say "KelyfOS cookbook — every recipe, run as written (E3-3)"
echo "  cookbook    $COOKBOOK"
echo "  kelyfos     $(kelyfos version 2>/dev/null || echo 'not on PATH')"
echo "  arch        $(uname -m)"

go run "$REPO/tools/cookbook" -in "$COOKBOOK" -out "$WORK/recipes" || {
  echo "the cookbook does not extract; nothing was run"
  exit 1
}

wanted=("$@")
for script in "$WORK"/recipes/*.sh; do
  name="$(basename "$script" .sh)"
  if [ "${#wanted[@]}" -gt 0 ] && [[ ! " ${wanted[*]} " == *" $name "* ]]; then
    continue
  fi

  say "recipe: $name"
  # Each recipe starts from a clean machine. A sandbox left behind by the
  # previous one makes the next one fail for a reason that has nothing to do
  # with it — `kelyfos exec` with several sandboxes running asks which one.
  pkill -f "$BIN/kelyfos run"  2>/dev/null
  pkill -f "$BIN/kelyfos fork" 2>/dev/null
  pkill -f "$BIN/kelyfos team" 2>/dev/null
  pkill -f "$BIN/kelyfos shim" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "${HOME:?}/.cache/kelyfos/run"/*

  start=$(date +%s)
  if timeout "${RECIPE_TIMEOUT:-600}" bash "$script" 2>&1 | sed 's/^/      /'; then
    pass "$name ($(( $(date +%s) - start ))s)"
  else
    fail "$name ($(( $(date +%s) - start ))s)"
  fi
done

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
