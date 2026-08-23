#!/usr/bin/env bash
# KelyfOS — Epic E2's proof demo: a real team doing real work (E2-9).
#
#   bash dev/demo-team.sh
#
# One master and four workers, the workers forked from a single template because
# their policy grants them no egress and a fork cannot carry a network identity
# (F-D19). The master splits a task over `team_send`, one worker asks it a
# clarifying question mid-task and waits for the answer, the workers coordinate
# their results through the permissioned team store, and the master assembles
# them. A worker then tries to message a worker it has no edge to, and is
# refused and audited — the refusal is part of the proof, not an accident.
#
# Everything below is driven through the real MCP tools over `kelyfos mcp`, on
# five real microVMs. Nothing is simulated and nothing is asserted that the
# flight recorder does not also record.
#
# Run this on bare KVM for the timing to mean anything: D15 makes a bare-KVM
# runner the environment that defines whether a number is met, and E2's spawn
# bar is one of those numbers.
set -uo pipefail

ARCH="${ARCH:-$(uname -m | sed -e 's/^arm64$/aarch64/' -e 's/^amd64$/x86_64/')}"
KELYFOS="${KELYFOS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/kelyfos}"
RUN_ROOT="${HOME}/.cache/kelyfos/run"
WORK="$(mktemp -d)"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

cleanup() {
  "$KELYFOS" team down >/dev/null 2>&1
  sleep 1
  pkill -f "$KELYFOS team up" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

# call <sandbox> <tool> <args-json> [hold-seconds] — one MCP tool call against
# one agent, returning the JSON-RPC result line.
#
# stdin is held open for the given seconds because a blocking tool (team_ask,
# team_recv) answers when the other side acts, not when the request is written.
call() {
  { printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
    sleep "${4:-5}"
  } | timeout 90 "$KELYFOS" mcp --sandbox "$1" 2>/dev/null | tail -1
}
# text <json> — the human-readable half of a tool result.
text() {
  python3 -c 'import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    print(""); raise SystemExit
r = d.get("result", {})
c = r.get("content", [])
print(c[0].get("text","") if c else "")' 2>/dev/null
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin).get('result',{}).get('structuredContent',{}).get('$1',''))" 2>/dev/null; }
sb() { python3 -c "import json;print([a['sandbox'] for a in json.load(open('$RUN_ROOT/team.json'))['agents'] if a['name']=='$1'][0])" 2>/dev/null; }
via() { python3 -c "import json;print([a.get('via','') for a in json.load(open('$RUN_ROOT/team.json'))['agents'] if a['name']=='$1'][0])" 2>/dev/null; }

say "KelyfOS agent teams — Epic E2 proof demo (E2-9)"
echo "  arch        $ARCH"
echo "  kelyfos     $("$KELYFOS" version 2>/dev/null | head -1)"
echo "  host        $(uname -srm), $(nproc) cpus"
if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT="$(systemd-detect-virt || true)"
else
  VIRT="$(grep -qE '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null && echo "vm (x86 hypervisor flag)" || echo unknown)"
fi
echo "  virtualised $VIRT"
if [ "$VIRT" != "none" ]; then
  echo "              this host is itself a guest, so every timing below is"
  echo "              informational; the bare-KVM runner decides (D15)."
fi

# ------------------------------------------------------------------ the team --
PROJ="$WORK/team"
mkdir -p "$PROJ/ws"
# The toml is a committed file, not a heredoc: the acceptance test says "the
# committed demo toml", and a policy a reader can open and edit is worth more
# than one buried in a script. It is copied rather than used in place so the run
# has its own workspace directory.
TOML="${DEMO_TOML:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/demo-team.toml}"
if [ ! -f "$TOML" ]; then
  echo "no demo policy at $TOML"; exit 1
fi
cp "$TOML" "$PROJ/kelyfos.toml"
echo "        $TOML"
grep -v '^ *#' "$PROJ/kelyfos.toml" | grep -v '^ *$' | sed 's/^/        /' 

say "1. kelyfos team up — five machines, four of them forked"
rm -f "$RUN_ROOT/team.json"
( cd "$PROJ" && "$KELYFOS" team up --arch "$ARCH" > team.log 2>&1 ) &
UPPID=$!
for _ in $(seq 1 600); do
  grep -q "team up in" "$PROJ/team.log" 2>/dev/null && break
  sleep 0.25
done
if ! grep -q "team up in" "$PROJ/team.log" 2>/dev/null; then
  sed 's/^/        /' "$PROJ/team.log"
  fail "the team never came up"
  say "Verdict"; printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
  printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
  exit 1
fi
sed 's/^/        /' "$PROJ/team.log"

SESS="$(python3 -c "import json;print(json.load(open('$RUN_ROOT/team.json'))['session'])")"
M="$(sb master)"
W1="$(sb worker-1)"; W2="$(sb worker-2)"; W3="$(sb worker-3)"; W4="$(sb worker-4)"

if [ -n "$M" ] && [ -n "$W1" ] && [ -n "$W2" ] && [ -n "$W3" ] && [ -n "$W4" ]; then
  pass "five agents are running: master + four workers"
else
  fail "the team is not five agents: $(python3 -c "import json;print(json.load(open('$RUN_ROOT/team.json'))['agents'])" 2>&1)"
fi

# The two boot paths must be visible rather than inferred (F-D19).
FORKED=0
for w in worker-1 worker-2 worker-3 worker-4; do
  [ "$(via $w)" = "fork" ] && FORKED=$((FORKED+1))
done
echo "        master booted: $(via master) · workers forked: $FORKED/4"
if [ "$FORKED" -eq 4 ] && [ "$(via master)" = "cold" ]; then
  pass "the no-egress workers were forked and the egress-granted master was not (F-D19)"
else
  fail "boot paths are not what F-D19 asks for: master=$(via master), $FORKED/4 workers forked"
fi

# The bar, measured rather than declared.
TOTAL_MS="$(sed -n 's/^team up in \([0-9]*\) ms.*/\1/p' "$PROJ/team.log" | head -1)"
echo "        total spawn time: ${TOTAL_MS} ms (E2 acceptance asks for < 1000 ms)"
if [ -n "$TOTAL_MS" ] && [ "$TOTAL_MS" -lt 1000 ]; then
  pass "total spawn time ${TOTAL_MS} ms is under the 1 s bar"
elif [ "$VIRT" != "none" ]; then
  skip "total spawn time ${TOTAL_MS} ms is over the 1 s bar on a nested host; the bare-KVM runner decides (D15)"
else
  fail "total spawn time ${TOTAL_MS} ms does not meet the 1 s bar"
fi

# The template's image is unlinked while four machines still have it mapped.
# That is safe on Linux — an unlinked inode survives as long as it is open — but
# it is the kind of safe that is worth proving rather than assuming.
LEFT="$(ls -d "$HOME/.cache/kelyfos/snapshots"/team-* 2>/dev/null | wc -l)"
ALIVE=0
for w in worker-1 worker-2 worker-3 worker-4; do
  P="$(call "$(sb $w)" team_peers '{}' 4 | text)"
  [ "$P" = "master" ] && ALIVE=$((ALIVE+1))
done
echo "        template snapshots left on disk: $LEFT · workers still answering: $ALIVE/4"
if [ "$LEFT" -eq 0 ] && [ "$ALIVE" -eq 4 ]; then
  pass "the template's image was deleted and all four forks kept running on it"
else
  fail "$LEFT template snapshot(s) left behind, $ALIVE/4 workers answering"
fi

say "2. kelyfos team ps — all five, their edges, and what they are using"
( cd "$PROJ" && "$KELYFOS" team ps ) 2>&1 | sed 's/^/        /'
PSOUT="$(cd "$PROJ" && "$KELYFOS" team ps 2>&1)"
if [ "$(printf '%s' "$PSOUT" | grep -c 'worker-')" -ge 4 ] && printf '%s' "$PSOUT" | grep -q 'master -> worker-1'; then
  pass "ps shows every agent, its edges and its live resource use"
else
  fail "ps is missing agents or edges"
fi

say "3. the task runs end to end: send, ask/reply, and the store"
# The master splits the work.
for w in worker-1 worker-2 worker-3 worker-4; do
  R="$(call "$M" team_send "{\"to\":\"$w\",\"body\":\"check supplier $w\"}" 4 | text)"
  echo "        master -> $w: $R"
done
SENT=0
for w in worker-1 worker-2 worker-3 worker-4; do
  W="$(sb $w)"
  GOT="$(call "$W" team_recv '{"timeout_ms":4000}' 4 | text)"
  echo "        $w received: $GOT"
  case "$GOT" in *"check supplier"*) SENT=$((SENT+1));; esac
done
if [ "$SENT" -eq 4 ]; then
  pass "the master split the task over team_send and every worker received its share"
else
  fail "only $SENT of 4 workers received their share of the task"
fi

# One worker asks the master a clarifying question, mid-task, and waits.
( call "$W1" team_ask '{"to":"master","body":"do we count discontinued lines?"}' 30 > "$WORK/ask.out" ) &
ASKPID=$!
sleep 3
Q="$(call "$M" team_recv '{"timeout_ms":8000}' 5)"
QTEXT="$(printf '%s' "$Q" | text)"
CORR="$(printf '%s' "$Q" | field correlate)"
echo "        master was asked: \"$QTEXT\" (correlate ${CORR:0:8}…)"
if [ -n "$CORR" ]; then
  call "$M" team_reply "{\"correlate\":\"$CORR\",\"body\":\"no, current lines only\"}" 5 >/dev/null
fi
wait "$ASKPID" 2>/dev/null
ANSWER="$(text < "$WORK/ask.out")"
echo "        worker-1's answer: \"$ANSWER\""
if [ "$ANSWER" = "no, current lines only" ]; then
  pass "a worker asked the master a question mid-task and got its answer back (team_ask/team_reply)"
else
  fail "the ask round trip did not complete: got \"$ANSWER\""
fi

# The workers coordinate through the store; the master assembles.
WROTE=0
for w in worker-1 worker-2 worker-3 worker-4; do
  W="$(sb $w)"
  R="$(call "$W" team_store_put "{\"key\":\"findings/$w\",\"value\":\"$w: 7 lines checked\"}" 4 | text)"
  case "$R" in *stored*) WROTE=$((WROTE+1));; esac
done
ASSEMBLED=0
for w in worker-1 worker-2 worker-3 worker-4; do
  R="$(call "$M" team_store_get "{\"key\":\"findings/$w\"}" 4 | text)"
  echo "        master read findings/$w: $R"
  case "$R" in *"lines checked"*) ASSEMBLED=$((ASSEMBLED+1));; esac
done
if [ "$WROTE" -eq 4 ] && [ "$ASSEMBLED" -eq 4 ]; then
  pass "four workers wrote their findings to the store and the master assembled all four"
else
  fail "the store round trip is incomplete: $WROTE written, $ASSEMBLED read back"
fi

# A worker may not read what another worker wrote: the key's rules say so.
DENIED="$(call "$W1" team_store_get '{"key":"findings/worker-2"}' 4 | text)"
echo "        worker-1 reading worker-2's findings: $DENIED"
case "$DENIED" in
  *denied*) pass "the store's per-key rules held: a worker may not read another's findings" ;;
  *)        fail "a worker read a key it has no rule for: $DENIED" ;;
esac

say "4. the deliberate edge violation — refused, and in the record"
VIOLATION="$(call "$W1" team_send '{"to":"worker-2","body":"go behind the master"}' 4 | text)"
echo "        worker-1 -> worker-2: $VIOLATION"
case "$VIOLATION" in
  *no_edge*) pass "a worker-to-worker message with no edge was refused to the agent's face" ;;
  *)         fail "a message crossed an edge that does not exist: $VIOLATION" ;;
esac

say "5. spawn under a declared budget — refused, refused, then allowed"
# An agent with no budget at all. The tool is not even listed for it, and the
# refusal still reaches the host and the log: a refusal the host never sees is a
# refusal that never reaches the record (F-D18).
# The message an agent sees is written for the agent; the machine-readable
# reason is a field in the record, and step 7 checks it there.
NOSPAWN="$(call "$W1" team_spawn '{"image":"dev"}' 4 | text)"
echo "        worker-1 (no budget):         $NOSPAWN"
case "$NOSPAWN" in
  *"no spawn budget"*) pass "an agent with no budget could not spawn, and the host said why" ;;
  *) fail "an agent with no spawn budget was not refused: $NOSPAWN" ;;
esac

# The master has a budget, but it names one image.
BADIMAGE="$(call "$M" team_spawn '{"image":"base"}' 4 | text)"
echo "        master (image not in budget): $BADIMAGE"
case "$BADIMAGE" in
  *"may not spawn"*) pass "a spawn outside the budget's image whitelist was refused" ;;
  *) fail "the budget's image whitelist did not hold: $BADIMAGE" ;;
esac

# One spawn is what the budget allows, and it works.
SPAWNED="$(call "$M" team_spawn '{"image":"dev"}' 25 | text)"
echo "        master (within budget):       $SPAWNED"
case "$SPAWNED" in
  master-spawn-*) pass "the master's one budgeted spawn succeeded: $SPAWNED" ;;
  *) fail "a spawn the budget allows did not happen: $SPAWNED" ;;
esac

# A second one is not.
OVER="$(call "$M" team_spawn '{"image":"dev"}' 5 | text)"
echo "        master (budget exhausted):    $OVER"
case "$OVER" in
  *denied*) pass "a spawn beyond the budget's count was refused" ;;
  *) fail "the budget's count did not hold: $OVER" ;;
esac

# The new worker joined with exactly one edge — to its spawner, and nowhere else.
if [ -n "$SPAWNED" ]; then
  NEW="$(sb "$SPAWNED")"
  if [ -n "$NEW" ]; then
    PEERS="$(call "$NEW" team_peers '{}' 4 | text)"
    echo "        $SPAWNED reaches:           $PEERS"
    if [ "$PEERS" = "master" ]; then
      pass "the spawned worker attached with a single edge, to its spawner (E2-0's one exception)"
    else
      fail "the spawned worker reaches more than its spawner: $PEERS"
    fi
  else
    fail "the spawned worker is not in the roster"
  fi
fi

say "6. kelyfos team down — every VM gone, every workspace synced"
echo "        before: $(ls "$PROJ/ws" | tr '\n' ' ')"
"$KELYFOS" exec --sandbox "$M" 'echo "assembled: 28 lines across 4 suppliers" > /work/report.txt' >/dev/null 2>&1
"$KELYFOS" team down 2>&1 | sed 's/^/        /'
for _ in $(seq 1 120); do [ -f "$RUN_ROOT/team.json" ] || break; sleep 0.5; done
wait "$UPPID" 2>/dev/null
sed -n '/stopping/,$p' "$PROJ/team.log" | sed 's/^/        /'
echo "        after:  $(ls "$PROJ/ws" | tr '\n' ' ')"
# pgrep -c prints 0 and *exits 1* when nothing matches, so a `|| echo 0`
# fallback appends a second zero and the comparison then fails on a machine
# where everything is right. Ask the question directly instead.
if pgrep firecracker >/dev/null 2>&1; then
  fail "$(pgrep -c firecracker) firecracker process(es) survived teardown"
else
  pass "every VM is gone"
fi
if [ -f "$PROJ/ws/report.txt" ]; then
  echo "        $PROJ/ws/report.txt: $(cat "$PROJ/ws/report.txt")"
  pass "the master's workspace was written back to the host"
else
  fail "the workspace was not synced back"
fi

say "7. the transcript verifies, and says who told what to whom"
"$KELYFOS" log --session "$SESS" --verify 2>&1 | sed 's/^/        /'
if "$KELYFOS" log --session "$SESS" --verify >/dev/null 2>&1; then
  pass "kelyfos log --verify passes for the whole team session"
else
  fail "the team's chain does not verify"
fi

# Every refusal the agents saw is also a machine-readable reason in the record.
# That is the half of "refused and audited" an agent cannot check for itself.
LOG="$("$KELYFOS" log --session "$SESS" 2>/dev/null)"
MISSING=""
for reason in no_edge denied no_spawn_budget image_not_permitted budget_exhausted; do
  printf '%s' "$LOG" | grep -q "$reason" || MISSING="$MISSING $reason"
done
printf '%s' "$LOG" | grep -E 'REFUSED|refused' | sed 's/^/        /'
if [ -z "$MISSING" ]; then
  pass "every refusal is in the record with its reason: no_edge, denied, and the three spawn reasons"
else
  fail "the record is missing reasons:$MISSING"
fi

# And the two boot paths are in it, which is what F-D19 asks be visible.
COLD="$(printf '%s' "$LOG" | grep -c 'via=cold')"
FORKS="$(printf '%s' "$LOG" | grep -c 'via=fork')"
echo "        ready events: $COLD cold, $FORKS forked"
if [ "$COLD" -ge 1 ] && [ "$FORKS" -ge 4 ]; then
  pass "the record says how every machine started (F-D19)"
else
  fail "the record has $COLD cold and $FORKS forked ready events"
fi
# Written where the operator can open it, and where CI can upload it, rather
# than into the temporary directory this script deletes on the way out.
EXPORT="${DEMO_OUT:-$PWD}/team.html"
"$KELYFOS" log --session "$SESS" --export "$EXPORT" 2>&1 | sed 's/^/        /'
if [ -f "$EXPORT" ]; then
  # Counted with grep -o, not grep -c: every lane heading is on one line of the
  # generated file, so counting *lines* would report one lane for any team.
  # The time gutter carries an extra class and is deliberately not counted here,
  # so this number is agents and only agents.
  LANES="$(grep -o 'class="lane-head"' "$EXPORT" | wc -l)"
  REFUSED="$(grep -o 'flow team-refused' "$EXPORT" | wc -l)"
  echo "        $EXPORT"
  echo "        agent lanes rendered: $LANES (five declared + the spawned worker) · refused flows: $REFUSED"
  if [ "$LANES" -ge 6 ] && [ "$REFUSED" -ge 1 ]; then
    pass "the export renders a lane per agent and the refused events with them"
  else
    fail "the export has $LANES lane headings and $REFUSED refused flows"
  fi
else
  fail "the export was not written"
fi

say "Verdict"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
[ "$FAILURES" -eq 0 ]
