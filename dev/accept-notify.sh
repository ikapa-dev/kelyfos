#!/usr/bin/env bash
# KelyfOS — --notify, and the four moments it exists for (E5-7).
#
#   bash dev/accept-notify.sh
#
# A desktop notification cannot be asserted from a script: there is no way to
# read what a notification daemon displayed. What *can* be checked is the thing
# that would actually be broken — whether kelyfos resolves and invokes the
# machine's notifier, with what arguments, at which moments. So a fake
# notify-send goes first on PATH and records every call.
#
# The other half is the promise that matters more than any notification: a run
# must not fail, hang or change its exit status because of one. That is checked
# with a notifier that fails, one that hangs, and one that does not exist.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
PASSES=0 FAILURES=0
SUMMARY=()

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

WORK="$(mktemp -d)"
cleanup() {
  pkill -f "kelyfos run" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

# A notify-send that records rather than displays. Everything below runs with
# this first on PATH, which is exactly how kelyfos finds the real one.
mkdir -p fake
cat > fake/notify-send <<'FAKE'
#!/usr/bin/env bash
{ printf 'CALL'; for a in "$@"; do printf '\t%s' "$a"; done; printf '\n'; } >> "$NOTIFY_LOG"
FAKE
chmod +x fake/notify-send
export PATH="$WORK/fake:$BIN:$PATH"
export NOTIFY_LOG="$WORK/notify.log"
: > "$NOTIFY_LOG"

say "KelyfOS — --notify"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml

say "no --notify, no notifications"
kelyfos run -- true > quiet.log 2>&1
check "$([ ! -s "$NOTIFY_LOG" ] && echo yes || echo no)" \
      "a run nobody asked to be notified about sends nothing"
check "$(grep -q 'notify' quiet.log && echo no || echo yes)" \
      "and does not mention notifications at all"

say "a run that finishes"
: > "$NOTIFY_LOG"
kelyfos run --notify -- sh -c 'exit 3' > finish.log 2>&1
code=$?
grep -E 'notify' finish.log | sed 's/^/  /'
sed 's/^/  /' "$NOTIFY_LOG"
check "$([ "$code" = "3" ] && echo yes || echo no)" "the exit status is untouched by notifying"
check "$(grep -q 'notify      via notify-send' finish.log && echo yes || echo no)" \
      "the run says which notifier it found"
check "$(grep -q 'kelyfos: run finished' "$NOTIFY_LOG" && echo yes || echo no)" \
      "a notification was sent when it finished"
check "$(grep -q 'exited 3 after' "$NOTIFY_LOG" && echo yes || echo no)" \
      "carrying the exit status and how long it took"
check "$(grep -q 'app-name=kelyfos' "$NOTIFY_LOG" && echo yes || echo no)" \
      "and saying who it is from"

say "the toml key does the same as the flag"
: > "$NOTIFY_LOG"
printf '[sandbox]\nimage = "%s"\nnotify = true\n' "$flavor" > kelyfos.toml
kelyfos run -- true > toml.log 2>&1
check "$(grep -q 'kelyfos: run finished' "$NOTIFY_LOG" && echo yes || echo no)" \
      "notify = true in kelyfos.toml notifies without the flag"
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml

say "a blocked domain"
: > "$NOTIFY_LOG"
(timeout 200 kelyfos run --notify --allow example.com > blocked.log 2>&1 &)
for i in $(seq 1 90); do grep -q "Ctrl-C" blocked.log 2>/dev/null && break; sleep 1; done
if ! grep -q "Ctrl-C" blocked.log; then
  fail "the sandbox never came up; the block check cannot run"
  tail -5 blocked.log
else
  kelyfos exec 'curl -s http://api.stripe.com/ ; curl -s http://api.stripe.com/ ; curl -s http://api.stripe.com/' >/dev/null 2>&1
  sleep 2
  sed 's/^/  /' "$NOTIFY_LOG"
  check "$(grep -q 'kelyfos: blocked' "$NOTIFY_LOG" && echo yes || echo no)" \
        "a refused domain raises a notification"
  check "$(grep -q 'api.stripe.com is not in this sandbox' "$NOTIFY_LOG" && echo yes || echo no)" \
        "naming the domain"
  check "$([ "$(grep -c 'kelyfos: blocked' "$NOTIFY_LOG")" = "1" ] && echo yes || echo no)" \
        "three refusals of the same domain are one notification, not three"
  check "$(grep -q 'add allow' "$NOTIFY_LOG" && echo no || echo yes)" \
        "the fix line stays on the terminal, where it can be acted on"
  pkill -f "kelyfos run" 2>/dev/null
  sleep 3
fi

say "a budget that expires"
: > "$NOTIFY_LOG"
kelyfos run --notify --max-runtime 5s > timeout.log 2>&1
code=$?
sed 's/^/  /' "$NOTIFY_LOG"
check "$([ "$code" = "124" ] && echo yes || echo no)" "the timeout still exits 124"
check "$(grep -q 'kelyfos: timed out' "$NOTIFY_LOG" && echo yes || echo no)" \
      "a timeout raises its own notification"
check "$(grep -q 'max_runtime budget of 5s' "$NOTIFY_LOG" && echo yes || echo no)" \
      "naming the budget that expired"

say "a review prompt waiting for somebody"
: > "$NOTIFY_LOG"
mkdir -p ws && echo original > ws/file.txt
# Through the toml key, because the review harness drives `kelyfos run --review`
# and this is the flag's other half — asking for it in the file has to work too.
printf '[sandbox]\nimage = "%s"\nworkspace = "./ws"\nnotify = true\n' "$flavor" > kelyfos.toml
python3 "$REPO/bin/reviewdrive.py" y "$WORK" > review.log 2>&1 || true
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml
sed 's/^/  /' "$NOTIFY_LOG"
check "$(grep -q 'kelyfos: waiting for you' "$NOTIFY_LOG" && echo yes || echo no)" \
      "the one question this product asks is notified before it is asked"

say "and a notifier that misbehaves cannot break a run"
cat > fake/notify-send <<'FAKE'
#!/usr/bin/env bash
echo "the notification daemon is unhappy" >&2
exit 1
FAKE
kelyfos run --notify -- sh -c 'echo still-ran; exit 0' > broken.log 2>&1
code=$?
check "$([ "$code" = "0" ] && echo yes || echo no)" "a notifier that fails does not fail the run"
check "$(grep -q 'still-ran' broken.log && echo yes || echo no)" "and the command still ran"

cat > fake/notify-send <<'FAKE'
#!/usr/bin/env bash
sleep 600
FAKE
start=$(date +%s)
timeout 200 kelyfos run --notify -- true > hung.log 2>&1
code=$?
elapsed=$(( $(date +%s) - start ))
echo "  the run took ${elapsed}s with a notifier that never returns"
check "$([ "$code" = "0" ] && echo yes || echo no)" "a notifier that hangs does not hang the run"
check "$([ "$elapsed" -lt 60 ] && echo yes || echo no)" "and does not hold teardown for long"

rm -f fake/notify-send
kelyfos run --notify -- true > none.log 2>&1
check "$([ "$?" = "0" ] && echo yes || echo no)" "a machine with no notifier at all still runs"
check "$(grep -q 'terminal bell only' none.log && echo yes || echo no)" \
      "and says it fell back to the terminal bell"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
