#!/usr/bin/env bash
# KelyfOS — the lifecycle: orphans and signals, committed as a suite (ST-1.9).
#
#   bash dev/accept-security-lifecycle.sh
#
# The audit's IA-M1 scenarios, machine-checked against the fixes ST-0.2 and
# ST-0.3 installed:
#
#   - a `snapshot restore` process killed with SIGKILL leaves its machine
#     orphaned — doctor now lists exactly that residue, and --reap-orphaned
#     removes all of it, after which a second restore of the same snapshot
#     works (the frozen proxy address and the jail name are free again);
#   - SIGTERM to the run process alone tears the machine down cleanly, with
#     and without a trailing command (ST-0.3's select case; the no-command
#     shape ci.yml already asserted on every push).
#
# This suite deliberately creates orphans on a shared VM. The guard rails:
# it uses its own private KELYFOS_CACHE (scope.sh), it creates the orphan it
# needs from its own snapshot, and before any of that it refuses to run if
# doctor already reports orphaned instances it cannot attribute — residue a
# previous run left is not this suite's to reap silently, and a suite that
# reaps strangers' orphans to make its own assertions cleaner is the host-wide
# kill wearing a suit (§8 trap 1, D83).
#
# No network beyond one --allow-less snapshot restore, which needs no egress.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-lifecycle

# Foreign-activity guard: the orphan battery must start from a doctor that
# sees nothing orphaned. Residue that already exists is named for the operator
# and left alone — this suite reaps only what it creates.
pre="$("$BIN/kelyfos" doctor 2>&1 | sed -n '/orphaned instances/p')"
case "$pre" in
  *"orphaned instances     none"*) pass "the machine starts with no orphaned instances" ;;
  *) fail "doctor already reports orphaned instances — reap them by hand first; this suite will not reap what it did not create"
     echo "  $pre"
     slab_done; exit 1 ;;
esac

say "the snapshot this suite restores"
# One run, no egress, one snapshot. `snapshot save` is a host command — it
# finds the running sandbox through the cache — and it stops the machine, so
# the run that held it ends on its own.
snap_host="$SLAB_WORK/snap"
mkdir -p "$snap_host"
aup -workspace "$snap_host"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
snap_out="$("$BIN/kelyfos" snapshot save --name sec-lab-lifecycle 2>&1)"
snap_rc=$?
check "$([ "$snap_rc" = "0" ] && echo yes || echo no)" "the snapshot saved (exit $snap_rc: $(head -c 60 <<<"$snap_out" | tr -d '\n'))"
for i in $(seq 1 60); do kill -0 "$AUP_PID" 2>/dev/null || break; sleep 1; done
scope_kill_kelyfos

say "SIGKILL a restore process: the orphan is listed, then reaped"
( "$BIN/kelyfos" snapshot restore --name sec-lab-lifecycle > "$SLAB_WORK/restore.log" 2>&1 & echo $! > "$SLAB_WORK/restore.pid" )
rpid="$(cat "$SLAB_WORK/restore.pid")"
for i in $(seq 1 120); do
  restore_id="$(sed -n 's/^sandbox \([0-9a-f]*\) restored.*/\1/p' "$SLAB_WORK/restore.log" 2>/dev/null | head -1)"
  [ -n "$restore_id" ] && break
  kill -0 "$rpid" 2>/dev/null || break
  sleep 0.5
done
# restore prints its own banner — `sandbox <id> restored from "name"` — and
# deliberately no sandbox= line (D84 scoped that to run, which is what the
# suites drive); the id comes from that banner here.
check "$([ -n "$restore_id" ] && echo yes || echo no)" "the restore booted a machine (id ${restore_id:-none})"
kill -9 "$rpid"
sleep 1

# ST-5.3's watchdog now fires where the audit found an immortal machine: the
# parent's death takes the VMM down and frees the network names without
# anybody asking. The assertion is the absence of what the audit measured.
vmm_gone=""
for i in $(seq 1 20); do
  [ -z "$(pgrep -x firecracker)" ] && { vmm_gone=yes; break; }
  sleep 0.5
done
check "$([ "$vmm_gone" = "yes" ] && echo yes || echo no)" \
      "the watchdog stopped the orphaned machine on its own"
after="$("$BIN/kelyfos" doctor 2>&1 | sed -n '/orphaned instances/p')"
case "$after" in
  *"orphaned instances     none"*) pass "doctor is clean — no orphan ever formed" ;;
  *) fail "doctor reports residue the watchdog should have prevented: $after" ;;
esac

say "the reaper still answers residue the watchdog cannot reach"
# A watchdog that was SIGKILLed itself cannot act — that residue is exactly
# what the doctor reaper exists for. Kill the watchdog first (it is this
# restore's other kelyfos child), then the restore, and doctor must list and
# reap the orphan the old-fashioned way.
( "$BIN/kelyfos" snapshot restore --name sec-lab-lifecycle > "$SLAB_WORK/restore3.log" 2>&1 & echo $! > "$SLAB_WORK/restore3.pid" )
r3pid="$(cat "$SLAB_WORK/restore3.pid")"
restore3_id=""
for i in $(seq 1 120); do
  restore3_id="$(sed -n 's/^sandbox \([0-9a-f]*\) restored.*/\1/p' "$SLAB_WORK/restore3.log" 2>/dev/null | head -1)"
  [ -n "$restore3_id" ] && break
  kill -0 "$r3pid" 2>/dev/null || break
  sleep 0.5
done
check "$([ -n "$restore3_id" ] && echo yes || echo no)" "the third restore booted (id ${restore3_id:-none})"
wd_killed=""
for c in $(pgrep -P "$r3pid"); do
  if [ "$(cat /proc/$c/comm 2>/dev/null)" = "kelyfos" ]; then
    kill -9 "$c" && wd_killed=yes
  fi
done
check "$([ "$wd_killed" = "yes" ] && echo yes || echo no)" "the watchdog itself was SIGKILLed"
kill -9 "$r3pid"
sleep 1
listing="$("$BIN/kelyfos" doctor 2>&1 | sed -n '/orphaned/,/reap-orphaned/p')"
if [ -n "$restore3_id" ] && grep -q "$restore3_id" <<<"$listing"; then
  pass "doctor lists the orphaned machine by id"
else
  fail "doctor does not list the orphaned machine by id ($(head -c 60 <<<"$listing" | tr -d '\n'))"
fi
check "$(grep -q "1 orphaned VMM" <<<"$listing" && echo yes || echo no)" \
      "and counts exactly one orphaned VMM — this run's, not a stranger's"

"$BIN/kelyfos" doctor --reap-orphaned >/dev/null 2>&1
after="$("$BIN/kelyfos" doctor 2>&1 | sed -n '/orphaned instances/p')"
case "$after" in
  *"orphaned instances     none"*) pass "the reaper removed it; doctor is clean again" ;;
  *) fail "doctor still reports orphans after the reap: $after" ;;
esac

say "a second restore of the same snapshot works after the reap"
( "$BIN/kelyfos" snapshot restore --name sec-lab-lifecycle > "$SLAB_WORK/restore2.log" 2>&1 & echo $! > "$SLAB_WORK/restore2.pid" )
r2pid="$(cat "$SLAB_WORK/restore2.pid")"
# A restore loads a memory image and re-pairs its addresses, which costs
# more than a fresh boot; the poll gives it a minute and a half and greps
# for the banner restore actually prints.
r2id=""
for i in $(seq 1 180); do
  r2id="$(sed -n 's/^sandbox \([0-9a-f]*\) restored.*/\1/p' "$SLAB_WORK/restore2.log" 2>/dev/null | head -1)"
  [ -n "$r2id" ] && break
  kill -0 "$r2pid" 2>/dev/null || break
  sleep 0.5
done
check "$([ -n "$r2id" ] && echo yes || echo no)" \
      "the frozen name, jail and addresses are free — the restore succeeds (id ${r2id:-none})"
# Stop the second restore's machine cleanly: a signal to the restore process
# itself, which its own handler tears down. An INT to its *children* dies at
# the sudo layer — sudo does not relay what it did not run in a foreground
# terminal — which the first version of this suite learned the hard way.
kill -TERM "$r2pid" 2>/dev/null
for i in $(seq 1 60); do kill -0 "$r2pid" 2>/dev/null || break; sleep 0.5; done
scope_kill_kelyfos
assert_eq "$(scope_live_pids | wc -l | tr -d ' ')" "0" \
      "and that restore's machine is stopped cleanly too"

say "SIGTERM to the run process alone, with and without a trailing command"
# Without a trailing command (ci.yml's shape): the context cancels, the
# deferred teardown runs.
aup_bare
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
bare_id="$AUP_ID"
kill -TERM "$AUP_PID"
for i in $(seq 1 60); do kill -0 "$AUP_PID" 2>/dev/null || break; sleep 0.5; done
check "$(kill -0 "$AUP_PID" 2>/dev/null && echo no || echo yes)" \
      "SIGTERM to a bare run pid tears it down"
check "$(grep -aq 'stopping\.\.\.' "$AUP_LOG" && echo yes || echo no)" \
      "through its own stop path (stopping... in the log)"
assert_eq "$(scope_live_pids | wc -l | tr -d ' ')" "0" \
      "and no machine is left behind"

# With a trailing command (ST-0.3's case): the same signal, the same result.
AUP_DWELL=300 aup
if [ -z "$AUP_ID" ]; then
  AUP_PID=""; AUP_ID="$bare_id"; adown; slab_done; exit 1
fi
kill -TERM "$AUP_PID"
for i in $(seq 1 60); do kill -0 "$AUP_PID" 2>/dev/null || break; sleep 0.5; done
check "$(kill -0 "$AUP_PID" 2>/dev/null && echo no || echo yes)" \
      "SIGTERM to a run pid with a trailing command tears it down too"
assert_contains "$(cat "$AUP_LOG")" "exited 143" \
      "the stopped child is announced with its own fate (128+TERM)"
assert_grep_event '"reason":\s*"interrupted"' "and the record says interrupted, not command_exited"
assert_eq "$(scope_live_pids | wc -l | tr -d ' ')" "0" \
      "and no machine is left behind here either"

slab_done
