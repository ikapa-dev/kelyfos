#!/usr/bin/env bash
# KelyfOS — a team's collective CPU cap is a claim until five guests try to
# exceed it together and the host watches the parent cgroup hold (E2-6).
#
#   bash dev/prove-team.sh
#
# This is the E2 acceptance line "host cgroup stats show the team's collective
# cap held while all five run stress-ng", measured rather than asserted. Every
# figure comes from the parent slice's own cpu.stat — the cgroup the cap is
# written on, so the number and the limit cannot be about different things. The
# guests are never asked what they used (F-D2).
#
# Run this on bare KVM. Decision D15 makes a bare-KVM x86_64 runner the
# environment that *defines* whether a number is met, and a team cap needs more
# demand than a single sandbox's — five VMs' worth — so a nested host is even
# less able to reach it. That outcome is reported as skipped, not as a pass.
set -uo pipefail

ARCH="${ARCH:-$(uname -m | sed -e 's/^arm64$/aarch64/' -e 's/^amd64$/x86_64/')}"
KELYFOS="${KELYFOS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/kelyfos}"
RUN_ROOT="${HOME}/.cache/kelyfos/run"

# The run directory has moved twice. The jailer put a sandbox's state at
# <run>/firecracker/<id>/root/sandbox.json rather than <run>/<id>/ (P5-1), and
# F19 moved it up one more level, to <run>/firecracker/<id>/sandbox.json, so
# that the chroot the VMM is dropped into cannot reach the host's own record of
# the machine.
#
# Resolve it instead of spelling any one layout, so a script that reads it keeps
# working across the change rather than quietly measuring nothing (P5-6). That
# was the stated intent last time and it still did not survive the next move,
# because only two of the three spellings were listed — which is the failure
# this comment exists to prevent, so: newest first, and add rather than replace.
statefile() { ls -t "$RUN_ROOT"/*/"$1"/sandbox.json "$RUN_ROOT"/*/"$1"/root/sandbox.json "$RUN_ROOT/$1/sandbox.json" 2>/dev/null | sed -n '1,1p'; }

WORK="$(mktemp -d)"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()
TEAM_CAP=200
# The team this run raised. Every command that means "the team" names it, so a
# peer's team on the same development box is neither read nor stopped by this
# script (P7-16, D79).
TEAM_NAME="proof"
SESSION=""
OWN_FC_PIDS=()

fc_pid() { local f="$RUN_ROOT/firecracker/$1/root/firecracker.pid"; [ -f "$f" ] && cat "$f" 2>/dev/null; }

cleanup() {
  [ -n "$SESSION" ] && "$KELYFOS" team down --team "$SESSION" >/dev/null 2>&1
  sleep 1
  pkill -f "$KELYFOS team up" 2>/dev/null
  sleep 1
  # This run's own machines only. `pgrep firecracker` is a host-wide question
  # and answering it with a kill is how a peer worktree loses its microVMs.
  for p in ${OWN_FC_PIDS[@]+"${OWN_FC_PIDS[@]}"}; do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

# write_toml <dir> <team cpu_quota, or "" for none> — five agents, star
# topology, no per-agent quota at all: the collective cap is then the only
# ceiling in the file, which is exactly what the acceptance sentence measures.
write_toml() {
  local dir="$1" cap="$2"
  mkdir -p "$dir"
  {
    printf '[team]\nname = "proof"\n\n'
    if [ -n "$cap" ]; then
      printf '[team.resources]\ncpu_quota = "%s%%"\n\n' "$cap"
    fi
    printf '[[team.agent]]\nname = "master"\nimage = "dev"\n'
    printf '  [team.agent.resources]\n  cpus = 2\n  mem = "512M"\n\n'
    printf '[[team.agent]]\nname = "worker"\nimage = "dev"\ncount = 4\n'
    printf '  [team.agent.resources]\n  cpus = 2\n  mem = "512M"\n\n'
    printf '[[team.edge]]\nfrom = "master"\nto = "worker-*"\n'
  } > "$dir/kelyfos.toml"
  sed 's/^/        /' "$dir/kelyfos.toml"
}

# up <dir> — boots the team declared in <dir> and sets TEAM_CGROUP / SBS.
up() {
  local dir="$1"
  ( cd "$dir" && "$KELYFOS" team up --arch "$ARCH" > team.log 2>&1 ) &
  UPPID=$!
  for _ in $(seq 1 600); do
    grep -q "team up in" "$dir/team.log" 2>/dev/null && break
    sleep 0.25
  done
  if ! grep -q "team up in" "$dir/team.log" 2>/dev/null; then
    echo "      the team never came up:"; sed 's/^/      /' "$dir/team.log"
    return 1
  fi
  SESSION="$("$KELYFOS" team ps --team "$TEAM_NAME" --json 2>/dev/null |
             python3 -c 'import json,sys;print(json.load(sys.stdin)["session"])' 2>/dev/null)"
  if [ -z "$SESSION" ]; then
    echo "      the team came up but did not report a session"; return 1
  fi
  local roster; roster="$("$KELYFOS" team ps --team "$SESSION" --json 2>/dev/null)"
  TEAM_CGROUP="$(printf '%s' "$roster" | python3 -c 'import json,sys;print((json.load(sys.stdin).get("budget") or {}).get("cgroup",""))' 2>/dev/null)"
  SBS="$(printf '%s' "$roster" | python3 -c 'import json,sys;print(" ".join(a["sandbox"] for a in json.load(sys.stdin)["agents"]))' 2>/dev/null)"
  local sb; for sb in $SBS; do
    local p; p="$(fc_pid "$sb")"; [ -n "$p" ] && OWN_FC_PIDS+=("$p")
  done
  echo "      $(grep -c 'ready in' "$dir/team.log") agents, $(grep 'team up in' "$dir/team.log")"
}

down() {
  [ -n "$SESSION" ] || return 0
  "$KELYFOS" team down --team "$SESSION" >/dev/null 2>&1
  # Asked of the product rather than of the layout: `team ps` on a team that has
  # stopped fails, and that is the same answer wherever its state lives.
  for _ in $(seq 1 120); do
    "$KELYFOS" team ps --team "$SESSION" >/dev/null 2>&1 || break
    sleep 0.5
  done
  wait "$UPPID" 2>/dev/null
  SESSION=""
}

# usage_usec <cgroup dir> — cumulative CPU microseconds the cgroup accounted.
usage_usec() { awk '/^usage_usec/{print $2}' "$1/cpu.stat" 2>/dev/null; }
throttled_usec() { awk '/^throttled_usec/{print $2}' "$1/cpu.stat" 2>/dev/null; }

# stress_agents — runs stress-ng on every agent at once and sets STRESS_WALL.
#
# The pids are collected and waited on by name. A bare `wait` would also wait
# for the backgrounded `team up`, which does not exit until the team is taken
# down — so the script would hang here forever, having proved nothing.
stress_agents() {
  local pids=() t0=$SECONDS
  for sb in $SBS; do
    "$KELYFOS" exec --sandbox "$sb" "stress-ng --cpu 2 --timeout 20s" >/dev/null 2>&1 &
    pids+=($!)
  done
  wait "${pids[@]}" 2>/dev/null
  STRESS_WALL=$(( SECONDS - t0 )); [ "$STRESS_WALL" -gt 0 ] || STRESS_WALL=1
}

# stress_all — drives every agent at once and reports cores' worth consumed by
# the whole team over the wall clock it took.
# children_usec <cgroup dir> — the sum of the direct children's CPU time.
children_usec() {
  local total=0 u
  for d in "$1"/*/; do
    u="$(usage_usec "${d%/}")"
    total=$(( total + ${u:-0} ))
  done
  echo "$total"
}

stress_all() {
  local cg="$1" before after wall
  before="$(usage_usec "$cg")"; before="${before:-0}"
  PARENT_BEFORE="$before"
  CHILD_BEFORE="$(children_usec "$cg")"
  stress_agents
  wall="$STRESS_WALL"
  after="$(usage_usec "$cg")"; after="${after:-0}"
  PARENT_AFTER="$after"
  CHILD_AFTER="$(children_usec "$cg")"
  TEAM_CORES="$(python3 -c "print(f'{($after - $before)/1e6/$wall:.2f}')")"
  TEAM_WALL="$wall"
  printf '        %s cpu-seconds over %ss = %s core(s) busy for the whole team\n' \
    "$(python3 -c "print(f'{($after - $before)/1e6:.2f}')")" "$wall" "$TEAM_CORES"
}

say "KelyfOS team resource budget — enforcement proof (E2-6)"
echo "  arch        $ARCH"
echo "  kelyfos     $("$KELYFOS" version 2>/dev/null | sed -n '1,1p')"
echo "  host        $(uname -srm), $(nproc) cpus"
if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT="$(systemd-detect-virt || true)"
else
  VIRT="$(grep -qE '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null && echo "vm (x86 hypervisor flag)" || echo unknown)"
fi
echo "  virtualised $VIRT"
if [ "$VIRT" != "none" ]; then
  echo "              this host is itself a guest, so the CPU figures below are"
  echo "              informational: a nested guest cannot generate the demand a"
  echo "              CPU cap needs to be visible at all, and a team needs five"
  echo "              times as much of it (D15)."
fi

# A 200% cap has to be *exceedable* or holding it proves nothing. Ten stressors
# across five guests need more than two cores of real machine underneath them.
if [ "$(nproc)" -lt 4 ]; then
  say "Prerequisite"
  skip "this host has $(nproc) cpus; a 200% team cap cannot be exceeded on fewer than 4, so nothing here would be measuring the cap"
  say "Verdict"
  printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
  printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
  exit 0
fi

# ------------------------------------------------------- the collective cap --
say "1. The collective cap — cpu.max on the team's parent slice"
dir="$WORK/capped"
write_toml "$dir" "$TEAM_CAP"
if ! up "$dir"; then
  fail "the capped team never came up"
else
  if [ -z "${TEAM_CGROUP:-}" ]; then
    fail "the team reported no cgroup path, so there is nothing to measure"
  else
    echo "        parent  $TEAM_CGROUP"
    echo "        cpu.max $(cat "$TEAM_CGROUP/cpu.max" 2>&1)"
    stress_all "$TEAM_CGROUP"

    # The ceiling, with room for the sampling interval.
    if python3 -c "import sys; sys.exit(0 if $TEAM_CORES <= $TEAM_CAP/100.0 * 1.1 else 1)"; then
      pass "the team's collective cap held: $TEAM_CORES cores' worth over ${TEAM_WALL}s against cpu_quota = ${TEAM_CAP}%"
    else
      fail "the team's collective cap was exceeded: $TEAM_CORES cores' worth against a ${TEAM_CAP}% ceiling"
    fi

    # A cap that was never approached reads exactly like one that held, so the
    # kernel is asked whether it actually had to throttle anybody.
    THROTTLED="$(throttled_usec "$TEAM_CGROUP")"; THROTTLED="${THROTTLED:-0}"
    echo "        throttled_usec $THROTTLED"
    if [ "$THROTTLED" -gt 0 ]; then
      pass "the cap bit: the kernel throttled the team for $(python3 -c "print(f'{$THROTTLED/1e6:.1f}')")s"
    else
      fail "the cap never bit: throttled_usec is 0, so this run did not test a limit"
    fi

    # Five unrelated cgroups would not add up. This is the assertion that
    # distinguishes a hierarchy from five E1-2 slices that happen to coexist.
    #
    # Compared as *deltas over the stress window*, not as absolutes. A cgroup's
    # counters are cumulative for the life of the directory, so a parent that
    # outlived a previous run would carry that run's CPU time while its children
    # started from zero — and the assertion would fail on a hierarchy that is
    # perfectly real. That is not hypothetical: it is what a second unprivileged
    # run of this script reported before the deltas were taken.
    CHILD_SUM=$(( CHILD_AFTER - CHILD_BEFORE ))
    PARENT_USE=$(( PARENT_AFTER - PARENT_BEFORE ))
    printf '        over the window: children %s usec, parent %s usec\n' "$CHILD_SUM" "$PARENT_USE"
    if [ "$CHILD_SUM" -gt 0 ] && python3 -c "import sys; sys.exit(0 if abs($CHILD_SUM - $PARENT_USE) <= 0.05 * max($PARENT_USE,1) else 1)"; then
      pass "the hierarchy is real: the children's CPU time adds up to the parent's, within 5%"
    else
      fail "the children do not add up to the parent ($CHILD_SUM vs $PARENT_USE) — these are not one tree"
    fi

    # Equal weights are what "divides contention fairly" means, and writing
    # them explicitly is what makes it something to read back rather than
    # assume.
    WEIGHTS="$(cat "$TEAM_CGROUP"/*/cpu.weight 2>/dev/null | sort -u | tr '\n' ' ')"
    echo "        cpu.weight across the children: $WEIGHTS"
    if [ "$(printf '%s' "$WEIGHTS" | wc -w)" -eq 1 ] && [ "${WEIGHTS% }" = "100" ]; then
      pass "no agent was privileged: every child's cpu.weight is 100"
    else
      fail "the children carry different weights: $WEIGHTS"
    fi
  fi
  CAPPED_CORES="${TEAM_CORES:-0}"
  down
  # The thing that must not outlive the team is the *cap*, not the directory.
  #
  # On the direct path KelyfOS rmdirs the parent itself, and a leaked cgroup
  # would otherwise be silent: rmdir refuses a populated one and the error is
  # discarded by design. On the systemd path the parent is a slice unit, KelyfOS
  # takes its runtime property back and systemd collects the empty slice when it
  # gets to it — which is not instant, and asserting on the directory alone
  # failed a correct teardown here before this comment existed.
  if [ -n "${TEAM_CGROUP:-}" ]; then
    for _ in $(seq 1 40); do
      [ -d "$TEAM_CGROUP" ] || break
      sleep 0.25
    done
    if [ ! -d "$TEAM_CGROUP" ]; then
      pass "teardown removed the team's slice: $TEAM_CGROUP is gone"
    else
      LEFTCAP="$(cat "$TEAM_CGROUP/cpu.max" 2>/dev/null || echo "gone")"
      LEFTPROCS="$(cat "$TEAM_CGROUP"/*/cgroup.procs "$TEAM_CGROUP/cgroup.procs" 2>/dev/null | wc -l)"
      echo "        the slice is still present: cpu.max=$LEFTCAP, $LEFTPROCS process(es) in it"
      if [ "$LEFTCAP" = "gone" ] || { [ "${LEFTCAP%% *}" = "max" ] && [ "$LEFTPROCS" -eq 0 ]; }; then
        pass "teardown took the team's cap back; the empty slice is systemd's to collect"
      else
        fail "the team's cap outlived the team: $TEAM_CGROUP still reads $LEFTCAP"
      fi
    fi
  fi
fi

# ------------------------------------------------------------ meaningfulness --
say "2. Is the comparison meaningful? — the same team with no collective cap"
dir="$WORK/uncapped"
write_toml "$dir" ""
if ! up "$dir"; then
  fail "the uncapped team never came up"
else
  # With no [team.resources] there is no parent slice, so the control run is
  # measured from the same place a single sandbox is: the VMM processes.
  before=0; after=0
  for sb in $SBS; do
    p="$(python3 -c "import json;print(json.load(open('$(statefile "$sb")'))['pid'])" 2>/dev/null)"
    v="$(python3 -c "
blob=open('/proc/$p/stat').read(); f=blob[blob.rindex(')')+1:].split()
print(int(f[11])+int(f[12]))" 2>/dev/null)"
    before=$(( before + ${v:-0} ))
  done
  stress_agents
  wall="$STRESS_WALL"
  for sb in $SBS; do
    p="$(python3 -c "import json;print(json.load(open('$(statefile "$sb")'))['pid'])" 2>/dev/null)"
    v="$(python3 -c "
blob=open('/proc/$p/stat').read(); f=blob[blob.rindex(')')+1:].split()
print(int(f[11])+int(f[12]))" 2>/dev/null)"
    after=$(( after + ${v:-0} ))
  done
  UNCAPPED_CORES="$(python3 -c "print(f'{($after - $before)/100.0/$wall:.2f}')")"
  printf '        uncapped team reached %s core(s) busy over %ss\n' "$UNCAPPED_CORES" "$wall"
  down

  if python3 -c "import sys; sys.exit(0 if $UNCAPPED_CORES > $TEAM_CAP/100.0 * 1.3 else 1)"; then
    pass "the comparison is meaningful: uncapped reached $UNCAPPED_CORES cores' worth against a ${TEAM_CAP}% cap"
  elif [ "$VIRT" != "none" ]; then
    skip "the team cap is untested here: uncapped only reached $UNCAPPED_CORES cores' worth on a nested host (D15)"
  else
    fail "uncapped only reached $UNCAPPED_CORES cores' worth — this machine cannot generate enough demand to test a ${TEAM_CAP}% team cap"
  fi
fi

# ------------------------------------------------------------------ verdict --
say "Verdict"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
[ "$FAILURES" -eq 0 ]
