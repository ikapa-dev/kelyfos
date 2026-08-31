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

# This run gets its own KELYFOS_CACHE and tears down only the machines under
# it (D79). The kills that used to be here were host-wide, and this harness is
# where the class was caught doing its damage: while a full run was going, a
# reviewing agent's `make test` went red with three internal/sandbox failures,
# "firecracker exited before the guest was ready: signal: terminated". Between
# every recipe is twenty-three times per run.
source "$REPO/dev/scope.sh"
scope_init cookbook

cleanup() {
  scope_teardown
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
  #
  # This run's own machines only. These lines used to be host-wide questions
  # answered with a kill, twenty-three times in a full run; they now stop the
  # kelyfos processes carrying this run's KELYFOS_CACHE and the Firecrackers
  # whose pid files are under it, and nothing else on the host. The cache
  # survives -- the next recipe wants the sessions this one wrote.
  scope_kill_machines
  # What is NOT left is the line that used to follow:
  #
  #     rm -rf "${HOME:?}/.cache/kelyfos/run"/*
  #
  # It deleted run/teams — every other team's state file on the host — and
  # run/firecracker/<id> for every live sandbox, twenty-three times in a full
  # run. Killing a peer's machines is bad; deleting the state that names them
  # takes away the recovery too, because `team down --team <session>` then has
  # no file to find. Nothing needs it for the NEXT recipe: every recipe now
  # stops the team and the machines it started (P7-16), a run directory whose
  # process is gone is skipped by `sandbox.Load` and by `RunningSessions` on
  # the `alive(PID)` check, so a stale one cannot make the next recipe
  # ambiguous, and the kills above already end anything still holding one.
  # Found by the adversarial review of P7-16, in the harness that runs the
  # recipes that round had just scoped.
  #
  # The trade, restated because D83 changed it. This paragraph used to say the
  # leftovers were "every sandbox on this host that the kills cut down, whoever
  # it belonged to", because the kills above asked `pgrep firecracker`. They no
  # longer do: scope_kill_machines stops this run's kelyfos processes and this
  # run's Firecrackers, so nothing a peer owns is cut down and nothing a peer
  # owns is left behind. The honest bound is now this run's own machines, and a
  # recipe that SUCCEEDS can still leave one, when its own trap has SIGTERMed a
  # backgrounded `kelyfos run` that is still tearing down as the next recipe's
  # kills fire.
  #
  # The `hasLiveRunDir` consequence that used to follow is gone too, and it is
  # worth saying why rather than deleting it. A leftover run directory used to
  # sit in the shared cache, where `hasLiveRunDir` in host/sessions.go is a bare
  # `os.Stat` feeding `sessionIsLive` — so `kelyfos sessions prune` SKIPPED that
  # session and `kelyfos sessions erase` REFUSED it outright for as long as the
  # directory existed. This run's directories are now inside its own
  # KELYFOS_CACHE and go with it at teardown, so they cannot pin anybody's
  # session against an erasure. That product behaviour is unchanged and still
  # applies to a leftover in the shared cache from any other source.

  start=$(date +%s)
  # Into a file rather than through a pipe, and that is the whole fix (P6-18).
  #
  # `timeout N bash "$script" | sed ...` does not bound a recipe, and the way it
  # fails is worse than not bounding it. Several recipes background a long-lived
  # process — `kelyfos run &` is the shape — and a backgrounded child inherits
  # the write end of that pipe. When the script then exits *quickly* (under
  # `set -e`, a failed command is enough), `timeout` never fires, bash is gone,
  # and the orphan still holds the pipe open. `sed` blocks on a read that will
  # never see EOF, and the pipeline hangs for as long as the job is allowed to
  # live.
  #
  # Measured, because the obvious theory was tested wrong once: a script that
  # *hangs* does not show this — `timeout` puts the child in its own process
  # group and signals the group, so the orphan dies with it. It is the script
  # that *fails fast* while leaving a child that hangs the reader. Both shapes
  # were run on Linux: piped, an orphan plus an immediate `false` hangs
  # indefinitely; redirected, the same script returns in 0s with rc=1.
  #
  # That is exactly what happened here. `pause-and-resume` fails on x86_64 in
  # 23 seconds with exit 1 — and through a pipe that 23-second failure became
  # 96 minutes of a 180-minute job whose log's last line was
  # `recipe: pause-and-resume` with no verdict after it. A file has no reader to
  # block: `timeout`'s own status is read directly, and 124 is reported as
  # TIMED OUT with the recipe's name.
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
