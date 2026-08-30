#!/usr/bin/env bash
# KelyfOS — Epic E2's acceptance test, run as written.
#
#   bash dev/accept-e2.sh
#
# The eight steps below are E2's acceptance list (docs/roadmap.md), in its
# order and with its numbers. They are here as a script rather than as a
# transcript so the next person can re-run them rather than believe them.
#
# Seven of the eight are what `dev/demo-team.sh` drives on five real microVMs,
# and the eighth — the collective cap holding while all five run stress-ng — is
# what `dev/prove-team.sh` measures from the parent cgroup. This script runs
# both and maps what they reported onto the list, rather than doing the same
# work a third time in a third way: three scripts that boot the same team is
# three places for the truth to drift.
#
# Binding numbers come from the bare-KVM reference (D15). Step 1's spawn time is
# a measurement and means nothing on a nested host; the rest are behaviour and
# mean the same everywhere.
set -uo pipefail

ARCH="${ARCH:-$(uname -m | sed -e 's/^arm64$/aarch64/' -e 's/^amd64$/x86_64/')}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KELYFOS="${KELYFOS:-$(cd "$HERE/.." && pwd)/bin/kelyfos}"
WORK="$(mktemp -d)"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

# step <n> <what the acceptance list asks for> <log> <marker...>
#
# Reports the acceptance item against the line the underlying proof printed, so
# a reader sees the claim and the evidence for it side by side.
step() {
  local n="$1" what="$2" log="$3"; shift 3
  local line=""
  for marker in "$@"; do
    line="$(grep -E "^  (PASS|SKIP|FAIL)  .*$marker" "$log" | sed -n '1,1p')"
    [ -n "$line" ] && break
  done
  if [ -z "$line" ]; then
    fail "$n. $what — nothing in $(basename "$log") reported on it"
    return
  fi
  printf '        %s\n' "$(printf '%s' "$line" | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/^  //')"
  case "$line" in
    *PASS*) pass "$n. $what" ;;
    *SKIP*) skip "$n. $what — the underlying proof skipped it" ;;
    *)      fail "$n. $what" ;;
  esac
}

say "KelyfOS Epic E2 — acceptance test (agent teams)"
echo "  arch        $ARCH"
echo "  kelyfos     $("$KELYFOS" version 2>/dev/null | sed -n '1,1p')"
echo "  host        $(uname -srm), $(nproc) cpus"
if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT="$(systemd-detect-virt || true)"
else
  VIRT="$(grep -qE '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null && echo vm || echo unknown)"
fi
echo "  virtualised $VIRT"

DEMO="$WORK/demo.log"
PROVE="$WORK/prove.log"

say "Running dev/demo-team.sh (steps 1-5, 7, 8)"
ARCH="$ARCH" KELYFOS="$KELYFOS" bash "$HERE/demo-team.sh" > "$DEMO" 2>&1
DEMO_RC=$?
sed -e 's/\x1b\[[0-9;]*m//g' "$DEMO" | grep -E '^  (PASS|FAIL|SKIP)|^  [0-9]+ passed' | sed 's/^/        /'

say "Running dev/prove-team.sh (step 6)"
ARCH="$ARCH" KELYFOS="$KELYFOS" bash "$HERE/prove-team.sh" > "$PROVE" 2>&1
PROVE_RC=$?
sed -e 's/\x1b\[[0-9;]*m//g' "$PROVE" | grep -E '^  (PASS|FAIL|SKIP)|^  [0-9]+ passed' | sed 's/^/        /'

say "The acceptance list, item by item"

step 1 "kelyfos team up boots five VMs; total spawn time recorded (cold path — the bar binds here)" \
  "$DEMO" "cold-path spawn time"
step 1 "  (the warm path, forking from a cached template, is faster)" \
  "$DEMO" "warm path is faster"
step 1 "  (and the two boot paths are the ones F-D26 asks for)" \
  "$DEMO" "no-egress workers were forked"
step 1 "  (the cold run fills the cache for the next one)" \
  "$DEMO" "cached a fork template in the background"
step 2 "kelyfos team ps shows all five, their edges, and live resource use against E1 caps" \
  "$DEMO" "ps shows every agent"
step 3 "the demo task completes through team_send/team_recv, one team_ask round trip, and the store" \
  "$DEMO" "asked the master a question mid-task"
step 3 "  (the store half: four workers wrote, the master assembled)" \
  "$DEMO" "wrote their findings to the store"
step 4 "a worker messaging a worker it has no edge to is refused, and the refusal is in the log" \
  "$DEMO" "no edge was refused"
step 4 "  (and the reason is in the record, not only in the message)" \
  "$DEMO" "every refusal is in the record"
step 5 "an agent without team.spawn is refused; a spawn beyond budget is refused; one budgeted spawn succeeds" \
  "$DEMO" "no budget could not spawn"
step 5 "  (the budgeted one)" "$DEMO" "budgeted spawn succeeded"
step 5 "  (beyond the count)" "$DEMO" "beyond the budget's count was refused"
step 5 "  (and the new worker has exactly one edge, to its spawner)" \
  "$DEMO" "single edge, to its spawner"
step 6 "host cgroup stats show the team's collective cap held while all five run stress-ng" \
  "$PROVE" "collective cap held"
step 6 "  (and the cap actually bit, so the measurement means something)" \
  "$PROVE" "the cap bit"
step 7 "kelyfos team down: all VMs gone, all workspaces synced" \
  "$DEMO" "every VM is gone"
step 7 "  (the workspace half)" "$DEMO" "workspace was written back"
step 8 "kelyfos log --verify passes for the whole session" \
  "$DEMO" "verify passes for the whole team session"
step 8 "  (and --export renders the lanes including the refused events)" \
  "$DEMO" "renders a lane per agent"

say "Verdict"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
printf '  underlying: demo-team.sh exit %d, prove-team.sh exit %d\n' "$DEMO_RC" "$PROVE_RC"
[ "$FAILURES" -eq 0 ]
