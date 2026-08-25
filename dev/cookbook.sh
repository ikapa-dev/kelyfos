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
  pkill -f "$BIN/kelyfos serve-mcp" 2>/dev/null
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
  pkill -f "$BIN/kelyfos serve-mcp" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "${HOME:?}/.cache/kelyfos/run"/*

  start=$(date +%s)
  # Into a file rather than through a pipe, and the reason is diagnostic
  # (P6-18).
  #
  # `pause-and-resume` stalled twice in a row on the x86_64 runner: 96 minutes
  # of a 180-minute job, and the log's last line was `recipe: pause-and-resume`
  # with no verdict after it. The 600-second cap did not produce one. **Why it
  # did not is still open** — the obvious theory, that a backgrounded
  # `kelyfos run &` holds the pipe open so `sed` never sees EOF, was tested on
  # Linux and is wrong: coreutils `timeout` puts the child in its own process
  # group and signals the group, so the orphan dies with the script.
  #
  # What this change buys is the thing that was missing while that question is
  # answered: a verdict. Output goes to a file, `timeout`'s own exit status is
  # read directly rather than through a pipeline, and 124 is reported as
  # TIMED OUT with the recipe's name — so the next occurrence says which recipe
  # and that it hung, in the log, at the moment it happens.
  out="$WORK/$name.out"
  timeout --kill-after=30 "${RECIPE_TIMEOUT:-600}" bash "$script" >"$out" 2>&1
  rc=$?
  sed 's/^/      /' "$out"
  if [ "$rc" -eq 0 ]; then
    pass "$name ($(( $(date +%s) - start ))s)"
  else
    # 124 is timeout's own verdict, and it is worth saying out loud: a recipe
    # that hung is a different defect from a recipe that failed.
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
      fail "$name — TIMED OUT after ${RECIPE_TIMEOUT:-600}s"
    else
      fail "$name ($(( $(date +%s) - start ))s, exit $rc)"
    fi
  fi
done

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
