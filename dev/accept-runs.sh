#!/usr/bin/env bash
# KelyfOS — run history, and what makes a rerun a rerun (E5-6).
#
#   bash dev/accept-runs.sh
#
# There is no run database: `kelyfos runs` reads the session records that were
# already being written. That is the claim worth checking, so this run does not
# only look at the listing — it checks that a run appears in it with the exit
# status it actually returned, that `rerun` reproduces the command *and its
# directory and its policy*, and that editing kelyfos.toml afterwards does not
# change what a rerun does.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"
PASSES=0 FAILURES=0
SUMMARY=()

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

WORK="$(mktemp -d)"
# This run gets its own KELYFOS_CACHE and tears down only the machines under
# it. The lines that used to be here -- `pkill -f "kelyfos run"` and
# `for p in $(pgrep firecracker); do kill "$p"; done` -- were host-wide
# questions answered with a kill, and on a machine running more than one
# worktree they took a peer's microVMs down with them (D79).
source "$REPO/dev/scope.sh"
scope_init accept-runs

cleanup() {
  scope_teardown
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — run history"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"

mkdir -p project && cd project
cat > kelyfos.toml <<TOML
[sandbox]
image = "$flavor"

[resources]
cpus = 2
TOML

say "a run that fails on purpose, so there is something to find"
kelyfos run -- sh -c 'echo the-original-run > /tmp/marker; kelyfos exec "echo from-inside" >/dev/null; exit 3' > run1.log 2>&1
code=$?
tail -2 run1.log | sed 's/^/  /'
check "$([ "$code" = "3" ] && echo yes || echo no)" "the run exits with what its command exited with"

say "it is in the history, with that status"
kelyfos runs -n 5 > runs.txt 2>&1
sed 's/^/  /' runs.txt
session="$(sed -n 2p runs.txt | awk '{print $1}')"
echo "  most recent: $session"
check "$(sed -n 2p runs.txt | awk '{print $5}' | grep -qx 3 && echo yes || echo no)" \
      "the exit status is in the listing"
check "$(grep -q 'the-original-run' runs.txt && echo yes || echo no)" \
      "and so is the command that was run"
check "$(sed -n 2p runs.txt | grep -q "$flavor" && echo yes || echo no)" \
      "and the image it booted"
check "$(sed -n 1p runs.txt | grep -q 'ID *WHEN *IMAGE *EXIT *TOOK *COMMAND' && echo yes || echo no)" \
      "the columns are the ones the plan asked for"

say "the history is the records, not a second copy of them"
# The strong form of the claim: one row per session directory, no more and no
# fewer. A separate index would drift from that the first time one was removed.
rows="$(kelyfos runs --all | tail -n +2 | wc -l)"
dirs=0
for d in "$KELYFOS_CACHE"/sessions/*/; do [ -d "$d" ] && dirs=$((dirs+1)); done
echo "  $rows rows, $dirs session directories"
check "$([ "$rows" = "$dirs" ] && echo yes || echo no)" \
      "there is one row per session record, and nothing else to keep in step"
check "$([ -f "$KELYFOS_CACHE"/sessions/"$session"/kelyfos.toml ] && echo yes || echo no)" \
      "the policy in force was frozen beside that session's record"

say "the policy changes underneath it"
cat >> kelyfos.toml <<'TOML'

[resources]
cpus = 1
TOML
echo "  kelyfos.toml now sets cpus = 1"

say "rerun says exactly what it is about to reproduce"
kelyfos rerun --print "$session" > provenance.txt 2>&1
sed 's/^/  /' provenance.txt
check "$(grep -q "rerunning session $session" provenance.txt && echo yes || echo no)" \
      "it names the session and when it ran"
check "$(grep -q "$WORK/project" provenance.txt && echo yes || echo no)" \
      "and the directory it was launched from"
check "$(grep -q 'frozen when that run started' provenance.txt && echo yes || echo no)" \
      "and that the policy is the frozen one, not the file as it is now"
check "$(grep -q 'the-original-run' provenance.txt && echo yes || echo no)" \
      "and the command itself"

say "and reruns it, from somewhere else entirely"
cd "$WORK"
kelyfos rerun "$session" > rerun.log 2>&1
code=$?
grep -E 'the-original-run|exited' rerun.log | sed 's/^/  /'
check "$([ "$code" = "3" ] && echo yes || echo no)" "the rerun exits 3, the way the original did"
check "$(grep -q 'the-original-run' rerun.log && echo yes || echo no)" "and ran the same command"
check "$(grep -q 'cpus = 1\|exceeds the ceiling' rerun.log && echo no || echo yes)" \
      "the edited kelyfos.toml did not affect it"

say "a prefix is enough, and an ambiguous one is not guessed at"
kelyfos rerun --print "${session:0:4}" > short.txt 2>&1
check "$(grep -q "$session" short.txt && echo yes || echo no)" "four characters find the session"
out="$(kelyfos rerun --print zzzzzzzz 2>&1)"
check "$(grep -q 'no recorded session starts with' <<<"$out" && echo yes || echo no)" \
      "and one that matches nothing says so, and points at kelyfos runs"

say "logs -f is the greppable live tail"
(timeout 120 kelyfos run --image "$flavor" > live.log 2>&1 &)
for i in $(seq 1 60); do grep -q "Ctrl-C" live.log 2>/dev/null && break; sleep 1; done
live="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
(timeout 25 kelyfos logs -f --session "$live" > tail.txt 2>&1 &)
sleep 2
kelyfos exec 'echo caught-by-the-tail' >/dev/null 2>&1
sleep 3
sed 's/^/  /' tail.txt | tail -4
check "$(grep -q 'caught-by-the-tail' tail.txt && echo yes || echo no)" \
      "a command run after the tail started shows up in it"
check "$(grep -q '{' tail.txt && echo no || echo yes)" \
      "and it is plain text, not JSON — the greppable sibling of watch"
scope_kill_kelyfos run
sleep 2

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
