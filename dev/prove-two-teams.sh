#!/usr/bin/env bash
# KelyfOS — two teams on one host do not collide, measured on real microVMs
# (P7-16, D70, D79).
#
#   bash dev/prove-two-teams.sh
#
# The defect this reproduces is not subtle once it is in front of you, and it
# was reported twice by reviewers who were not looking for it. Every team wrote
# one `run/team.json`, and `team up` guarded it with a `stat` taken tens of
# seconds before the matching write — so two teams started together both passed
# the guard, both booted, and the second's write replaced the first's state.
# After that `team ps` described the wrong team and `team down` signalled the
# wrong process. The team's parent cgroup was named for the team's *name*, so
# two checkouts of one project shared one slice — and stopping one team ran
# `systemctl --user stop` on it, which stops every scope in it, including the
# other team's Firecrackers.
#
# Against the commit before the fix this script reports, live, one `team down`
# killing four machines belonging to two teams. Against the fix it passes every
# line.
#
# Both teams are called "review", deliberately. That is what two worktrees of
# one project produce, which is the reproduction the reviewers hit, and it is
# what makes the name useless as a key.
#
# It is a behaviour proof, not a measurement: nothing here is a number, so
# unlike dev/prove-team.sh it means the same on a nested host as on bare KVM.
# It boots four microVMs and holds them for about a minute.
set -uo pipefail

ARCH="${ARCH:-$(uname -m | sed -e 's/^arm64$/aarch64/' -e 's/^amd64$/x86_64/')}"
KELYFOS="${KELYFOS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/kelyfos}"
RUN_ROOT="${KELYFOS_CACHE:-$HOME/.cache/kelyfos}/run"
WORK="$(mktemp -d)"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

# This run's own two teams, and this run's own Firecrackers. Nothing below asks
# the host a question it could answer about somebody else's team: that is the
# defect, one layer out, and dev/demo-team.sh already paid for it once (S20).
A_SESSION=""; B_SESSION=""; B_STOPPED=""
A_PIDS=(); B_PIDS=()
A_UP=""; B_UP=""

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

# The jailer writes one pid file per sandbox at
# <run>/firecracker/<id>/root/firecracker.pid, the same run-directory shape
# internal/sandbox.jailRunDir builds. Read while the machines exist, because
# teardown removes the directory holding it.
fc_pid() { local f="$RUN_ROOT/firecracker/$1/root/firecracker.pid"; [ -f "$f" ] && cat "$f" 2>/dev/null; }

cleanup() {
  [ -n "$A_SESSION" ] && "$KELYFOS" team down --team "$A_SESSION" >/dev/null 2>&1
  [ -n "$B_SESSION" ] && "$KELYFOS" team down --team "$B_SESSION" >/dev/null 2>&1
  sleep 2
  for p in ${A_PIDS[@]+"${A_PIDS[@]}"} ${B_PIDS[@]+"${B_PIDS[@]}"}; do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

verdict() {
  say "Verdict"
  printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
  printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
  [ "$FAILURES" -eq 0 ]
}

say "KelyfOS — two teams on one host (P7-16)"
echo "  arch        $ARCH"
echo "  kelyfos     $("$KELYFOS" version 2>/dev/null | sed -n '1,1p')"
echo "  run root    $RUN_ROOT"

for d in alpha beta; do
  mkdir -p "$WORK/$d"
  cat > "$WORK/$d/kelyfos.toml" <<'TOML'
[team]
name = "review"

  # A collective cap, so each team asks for a parent cgroup — which is the
  # second half of what collided, and cannot be checked without one.
  [team.resources]
  cpu_quota = "200%"

[[team.agent]]
name  = "lead"
image = "dev"

[[team.agent]]
name  = "hand"
image = "dev"

[[team.edge]]
from = "lead"
to   = "hand"
TOML
done

say "1. both teams up at once, both called \"review\""
( cd "$WORK/alpha" && "$KELYFOS" team up --arch "$ARCH" ) > "$WORK/alpha.log" 2>&1 &
A_UP=$!
( cd "$WORK/beta"  && "$KELYFOS" team up --arch "$ARCH" ) > "$WORK/beta.log"  2>&1 &
B_UP=$!
for f in alpha beta; do
  for _ in $(seq 1 600); do grep -q 'team up in' "$WORK/$f.log" 2>/dev/null && break; sleep 0.25; done
done
UPS=0
for f in alpha beta; do
  if grep -q 'team up in' "$WORK/$f.log" 2>/dev/null; then
    UPS=$((UPS+1)); echo "        $f: $(grep 'team up in' "$WORK/$f.log")"
  else
    echo "        $f did not come up:"; sed 's/^/          /' "$WORK/$f.log"
  fi
done
if [ "$UPS" -eq 2 ]; then
  pass "two teams of one name are running at once"
else
  fail "only $UPS of 2 teams came up"
  verdict; exit 1
fi

say "2. with two up, nothing is answered by guessing"
if "$KELYFOS" team ps > "$WORK/ps.log" 2>&1; then
  fail "\`team ps\` picked one of two teams"
else
  sed 's/^/        /' "$WORK/ps.log"
  if grep -q -- '--team' "$WORK/ps.log"; then
    pass "\`team ps\` refuses to guess and says how to name one"
  else
    fail "the refusal does not say how to name one"
  fi
fi

# Each team's session comes from its own `team up` output. Asking the host for
# "the team called review" is the ambiguity this script is about.
A_SESSION="$(sed -n 's/^session \([0-9a-f][0-9a-f]*\)$/\1/p' "$WORK/alpha.log" | sed -n '1,1p')"
B_SESSION="$(sed -n 's/^session \([0-9a-f][0-9a-f]*\)$/\1/p' "$WORK/beta.log"  | sed -n '1,1p')"
if [ -z "$A_SESSION" ] || [ -z "$B_SESSION" ] || [ "$A_SESSION" = "$B_SESSION" ]; then
  fail "the two teams did not report two distinct sessions: '$A_SESSION' / '$B_SESSION'"
  verdict; exit 1
fi
echo "        alpha session $A_SESSION"
echo "        beta  session $B_SESSION"
for s in "$A_SESSION" "$B_SESSION"; do
  grep -q "$s" "$WORK/ps.log" || fail "the refusal does not name session $s, so it cannot be picked"
done

roster() { "$KELYFOS" team ps --team "$1" --json 2>/dev/null; }
sandboxes() { roster "$1" | python3 -c 'import json,sys;print(" ".join(a["sandbox"] for a in json.load(sys.stdin)["agents"]))' 2>/dev/null; }
cgroup()  { roster "$1" | python3 -c 'import json,sys;print((json.load(sys.stdin).get("budget") or {}).get("cgroup",""))' 2>/dev/null; }
alive_of() { roster "$1" | python3 -c 'import json,sys;a=json.load(sys.stdin)["agents"];print(sum(1 for x in a if x["alive"]),len(a))' 2>/dev/null; }

A_SBS="$(sandboxes "$A_SESSION")"; B_SBS="$(sandboxes "$B_SESSION")"
for s in $A_SBS; do p="$(fc_pid "$s")"; [ -n "$p" ] && A_PIDS+=("$p"); done
for s in $B_SBS; do p="$(fc_pid "$s")"; [ -n "$p" ] && B_PIDS+=("$p"); done
echo "        alpha sandboxes: $A_SBS  (pids ${A_PIDS[*]:-none})"
echo "        beta  sandboxes: $B_SBS  (pids ${B_PIDS[*]:-none})"

say "3. nothing is shared between them"
SHARED=""
for a in $A_SBS; do for b in $B_SBS; do [ "$a" = "$b" ] && SHARED="$a"; done; done
if [ -n "$SHARED" ]; then
  fail "both teams claim sandbox $SHARED"
elif [ -z "$A_SBS" ] || [ -z "$B_SBS" ]; then
  fail "a team reports no sandboxes at all: '$A_SBS' / '$B_SBS'"
else
  pass "each team's roster is its own"
fi
if [ -f "$RUN_ROOT/teams/$A_SESSION.json" ] && [ -f "$RUN_ROOT/teams/$B_SESSION.json" ]; then
  pass "two teams, two state files under run/teams"
else
  fail "one of the two state files is missing under $RUN_ROOT/teams"
fi
if [ -e "$RUN_ROOT/team.json" ]; then
  fail "the host-wide run/team.json is back"
else
  pass "there is no host-wide run/team.json to collide over"
fi

A_CG="$(cgroup "$A_SESSION")"; B_CG="$(cgroup "$B_SESSION")"
echo "        alpha cgroup: ${A_CG:-none}"
echo "        beta  cgroup: ${B_CG:-none}"
if [ -z "$A_CG" ] && [ -z "$B_CG" ]; then
  skip "neither team got a cgroup parent on this host, so the slice half cannot be checked here"
elif [ -z "$A_CG" ] || [ -z "$B_CG" ]; then
  fail "one team got a cgroup parent and the other did not: '$A_CG' / '$B_CG'"
elif [ "$A_CG" = "$B_CG" ]; then
  fail "both teams landed in one cgroup parent: $A_CG — stopping either stops both"
else
  pass "each team has its own cgroup parent"
fi

say "4. one team is torn down; the other must not notice"
"$KELYFOS" team down --team "$B_SESSION" 2>&1 | sed 's/^/        /'
wait "$B_UP" 2>/dev/null
B_UP=""
sleep 2

STILL=()
for p in ${B_PIDS[@]+"${B_PIDS[@]}"}; do kill -0 "$p" 2>/dev/null && STILL+=("$p"); done
if [ "${#STILL[@]}" -eq 0 ]; then
  pass "every machine of the team that was stopped is gone"
else
  fail "${#STILL[@]} machine(s) of the stopped team survived: ${STILL[*]}"
fi
# Kept for the verify step below; B_SESSION is cleared so cleanup does not try
# to stop a team that is already down.
B_STOPPED="$B_SESSION"
B_SESSION=""; B_PIDS=()

# The line this whole script exists for.
GONE=()
for p in ${A_PIDS[@]+"${A_PIDS[@]}"}; do kill -0 "$p" 2>/dev/null || GONE+=("$p"); done
if [ "${#GONE[@]}" -eq 0 ]; then
  pass "every machine of the OTHER team is still running"
else
  fail "${#GONE[@]} machine(s) of the untouched team were killed with it: ${GONE[*]}"
fi

if [ -f "$RUN_ROOT/teams/$A_SESSION.json" ]; then
  pass "the untouched team's state file is still there"
else
  fail "tearing one team down removed the other team's state"
fi
if [ -n "$A_CG" ]; then
  if [ -d "$A_CG" ]; then
    pass "the untouched team's cgroup parent is still there"
  else
    fail "tearing one team down removed the other team's cgroup parent ($A_CG)"
  fi
fi
LEFT="$(alive_of "$A_SESSION")"
echo "        the untouched team reports $LEFT agents alive/total"
if [ "$LEFT" = "2 2" ]; then
  pass "\`team ps\` on the untouched team still reports every agent alive"
else
  fail "the untouched team reports $LEFT"
fi

# And the common case is unchanged: one team up, no flag.
if "$KELYFOS" team ps > "$WORK/ps2.log" 2>&1; then
  pass "with one team left, \`team ps\` needs no --team"
else
  fail "\`team ps\` refuses with only one team running:"; sed 's/^/        /' "$WORK/ps2.log"
fi

say "5. each team's own record verifies on its own"
for s in "$A_SESSION" "$B_STOPPED"; do
  if "$KELYFOS" log --session "$s" --verify 2>&1 | grep -q 'chain intact'; then
    pass "session $s verifies"
  else
    fail "session $s does not verify: $("$KELYFOS" log --session "$s" --verify 2>&1 | sed -n '1,2p')"
  fi
done

say "6. the remaining team comes down cleanly too"
"$KELYFOS" team down --team "$A_SESSION" 2>&1 | sed 's/^/        /'
wait "$A_UP" 2>/dev/null
A_UP=""
sleep 2
STILL=()
for p in ${A_PIDS[@]+"${A_PIDS[@]}"}; do kill -0 "$p" 2>/dev/null && STILL+=("$p"); done
if [ "${#STILL[@]}" -eq 0 ]; then
  pass "every machine gone"
else
  fail "${#STILL[@]} machine(s) survived: ${STILL[*]}"
fi
A_SESSION=""; A_PIDS=()
LEFTOVER="$(ls "$RUN_ROOT/teams"/*.json 2>/dev/null | wc -l | tr -d ' ')"
if [ "$LEFTOVER" = "0" ]; then
  pass "no team state left behind"
else
  fail "$LEFTOVER team state file(s) left behind under $RUN_ROOT/teams"
fi

verdict
