#!/usr/bin/env bash
# KelyfOS — the resource ceilings, committed as a suite (ST-1.5).
#
#   bash dev/accept-security-caps.sh
#
# The audit's cap scenarios, machine-checked: a policy ceiling is a maximum
# and never a default, so a flag above it is refused pre-boot with the file
# and line the ceiling came from; the guest sees the machines it is given —
# no more cores, no more memory than the cap says; a runtime budget fires and
# stops the run gracefully with timeout's own exit status; and a workspace
# above its disk ceiling is refused before anything boots. Ceilings that
# only report are walls with a door in them; these are checked from both
# sides — the refusal and the guest's own view.
#
# No network anywhere in it.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-caps

say "a flag above a policy ceiling is refused before boot"
# Ceilings live in [resources] — a ceiling, never a default; [sandbox]'s
# vcpus is what a flag may override freely.
printf '[resources]\ncpus = 2\n' > kelyfos.toml
ceil_out="$("$BIN/kelyfos" run -cpus 4 -- sleep 5 2>&1)"
ceil_rc=$?
check "$([ "$ceil_rc" != "0" ] && echo yes || echo no)" "the run refuses before anything boots (exit $ceil_rc)"
assert_contains "$ceil_out" "[ceiling.flag]" "the refusal names its denial ID"
assert_contains "$ceil_out" "kelyfos.toml" "and the file the ceiling came from"
assert_contains "$ceil_out" "cpus" "and the key that set it"

say "the guest sees the machine the cap describes"
aup -cpus 1 -mem 256M
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
assert_eq "$(ax 'nproc' 2>/dev/null | tr -d ' ')" "1" \
      "the guest sees exactly the cores it was given"
mem_kb="$(ax 'grep MemTotal /proc/meminfo' 2>/dev/null | awk '{print $2}')"
check "$([ -n "$mem_kb" ] && [ "$mem_kb" -lt 262144 ] && [ "$mem_kb" -gt 180000 ] && echo yes || echo no)" \
      "and its MemTotal (${mem_kb:-unknown} kB) sits under the 256M cap, not beside a host-sized number"
adown

say "the runtime budget fires and stops gracefully"
# aup appends its own trailing sleep; the budget is made shorter than the
# sleep so the budget, not the command, is what ends the run.
AUP_DWELL=300 AUP_MAX_RUNTIME="15s" aup
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
for i in $(seq 1 90); do
  kill -0 "$AUP_PID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$AUP_PID" 2>/dev/null; then
  fail "the max-runtime budget stopped the run (still alive after 90 s)"
  scope_kill_machines run
else
  pass "the max-runtime budget stopped the run on its own"
  assert_contains "$(cat "$AUP_LOG")" "max_runtime budget of 15s expired" \
        "the run says which budget fired and when"
  assert_contains "$(cat "$AUP_LOG")" "exited 124" \
        "and exits with timeout's own status, the way a budgeted command should"
  assert_grep_event '"type":\s*"resource.timeout"' "the record carries the timeout event"
  assert_grep_event '"reason":\s*"timeout"' "and session.end says the run ended on a timeout"
  assert_eq "$(scope_live_pids | wc -l | tr -d ' ')" "0" \
        "and the stop was graceful — no machine left behind"
fi

say "a workspace above its disk ceiling is refused pre-boot"
big="$SLAB_WORK/big"
mkdir -p "$big"
dd if=/dev/zero of="$big/blob" bs=1M count=4 status=none
disk_out="$("$BIN/kelyfos" run -image dev -workspace "$big" -disk 1M -- sleep 5 2>&1)"
disk_rc=$?
check "$([ "$disk_rc" != "0" ] && echo yes || echo no)" "the run is refused, not booted with a lie"
assert_contains "$disk_out" "over the 1048576 byte ceiling" \
      "the refusal states the packed size against the ceiling, before anything boots"

slab_done
