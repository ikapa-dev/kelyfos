#!/usr/bin/env bash
# KelyfOS — Epic E5's acceptance: recreate & verify.
#
#   bash dev/accept-e5.sh
#
# The epic's claim is that the daily driver feels like one, and every item here
# is one of the nine checks the plan wrote down before any of it was built. It
# runs the real binary against real microVMs; nothing here is mocked except the
# desktop notifier, which cannot be read back from a script.
#
# The per-task acceptances (accept-shell, accept-denials, accept-forward,
# accept-runs, accept-notify) go deeper on each feature. This one is the epic's
# own list, end to end, in one session.
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
killall_kelyfos() {
  pkill -f "kelyfos run" 2>/dev/null
  pkill -f "kelyfos resume" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  sleep 1
}
cleanup() {
  killall_kelyfos
  kelyfos sessions rm t1 >/dev/null 2>&1
  rm -rf "$WORK"
}

# A notifier that records rather than displays, first on PATH — which is how
# kelyfos finds the real one.
mkdir -p "$WORK/fake"
cat > "$WORK/fake/notify-send" <<'FAKE'
#!/usr/bin/env bash
{ printf 'CALL'; for a in "$@"; do printf '\t%s' "$a"; done; printf '\n'; } >> "$NOTIFY_LOG"
FAKE
chmod +x "$WORK/fake/notify-send"
export PATH="$WORK/fake:$BIN:$PATH"
export NOTIFY_LOG="$WORK/notify.log"
: > "$NOTIFY_LOG"

trap cleanup EXIT
cd "$WORK"

say "KelyfOS — Epic E5 acceptance: recreate & verify"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
echo "  image    $flavor"
killall_kelyfos
kelyfos sessions rm t1 >/dev/null 2>&1

# ---------------------------------------------------------------- 1 and 2 ----
say "1. a paused session is the same machine, not a copy of its files"
mkdir -p project && cd project
cat > kelyfos.toml <<TOML
[sandbox]
image = "$flavor"

[resources]
cpus = 2
TOML

kelyfos run > run1.log 2>&1 &
for _ in $(seq 1 90); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done
kelyfos exec "echo the-thing-i-was-doing > /tmp/scratch-note" >/dev/null 2>&1
kelyfos exec "cat /tmp/scratch-note" | sed 's/^/  /'
kelyfos pause --as t1 > pause.log 2>&1
grep -E 'stored|resume it with' pause.log | sed 's/^/  /'

# Every kelyfos process, gone. Nothing is holding this in memory anywhere.
killall_kelyfos
check "$(pgrep -f 'kelyfos run' >/dev/null && echo no || echo yes)" \
      "every kelyfos process was killed before the resume"
check "$(kelyfos sessions | grep -q t1 && echo yes || echo no)" \
      "the paused session survives with nothing running"

say "2. and the policy it comes back under is the one it was frozen with"
cat > kelyfos.toml <<TOML
[sandbox]
image = "$flavor"
allow = ["example.com"]

[resources]
cpus = 4
TOML
kelyfos resume t1 > resume.log 2>&1 &
for _ in $(seq 1 90); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done
scratch="$(kelyfos exec "cat /tmp/scratch-note" 2>&1)"
echo "  $scratch"
grep -E 'since changed|difference' resume.log | sed 's/^/  /'
check "$(grep -q 'the-thing-i-was-doing' <<<"$scratch" && echo yes || echo no)" \
      "the file in guest scratch is still there — full state, not a workspace copy"
check "$(grep -q 'has since changed' resume.log && echo yes || echo no)" \
      "the resume warns that the policy changed underneath it"
check "$(grep -q 'cpus 2 → 4' resume.log && echo yes || echo no)" \
      "naming the difference rather than telling somebody to go and diff two files"
check "$(grep -q 'frozen copy' resume.log && echo yes || echo no)" \
      "and says it is running under the frozen one"
killall_kelyfos
kelyfos sessions rm t1 >/dev/null 2>&1
cd "$WORK"

# ---------------------------------------------------------------------- 3 ----
say "3. --review shows A/M/D and does not write until somebody says so"
printf '[sandbox]\nimage = "%s"\nworkspace = "./ws"\n' "$flavor" > kelyfos.toml
mkdir -p ws
echo one   > ws/keep.txt
echo two   > ws/change.txt
echo three > ws/remove.txt
before="$(cd ws && find . -type f | sort | xargs sha256sum)"
guest='echo added > /work/new.txt; echo changed > /work/change.txt; rm /work/remove.txt; sync'

python3 "$REPO/bin/reviewdrive.py" n "$WORK" "$guest" > review-n.log 2>&1
sed 's/^/  /' review-n.log
after="$(cd ws && find . -type f | sort | xargs sha256sum)"
check "$(grep -qE '1 added, 1 modified, 1 deleted' review-n.log && echo yes || echo no)" \
      "the summary matches what the sandbox actually did"
check "$([ "$before" = "$after" ] && echo yes || echo no)" \
      "answering n leaves the host directory byte-identical"
check "$([ -f ws.kelyfos-out/new.txt ] && echo yes || echo no)" \
      "and routes the results to .kelyfos-out instead"
rm -rf ws.kelyfos-out

python3 "$REPO/bin/reviewdrive.py" y "$WORK" "$guest" > review-y.log 2>&1
check "$([ -f ws/new.txt ] && grep -q changed ws/change.txt && [ ! -e ws/remove.txt ] && echo yes || echo no)" \
      "answering y syncs the add, the edit and the delete"

# ---------------------------------------------------------------------- 4 ----
say "4. kelyfos shell is a real terminal, and records only what it promised"
mkdir -p shellwork && cd shellwork
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml
kelyfos run > shellrun.log 2>&1 &
for _ in $(seq 1 90); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done
shell_session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
python3 "$REPO/bin/shelldrive.py" "$PWD" > shell.log 2>&1
sed 's/^/  /' shell.log | sed -n '1,8p'
check "$(grep -q 'exit: 7' shell.log && echo yes || echo no)" "the shell's exit status comes back"
check "$(grep -q '/dev/pts/' shell.log && echo yes || echo no)" "it is a terminal, not a pipe"
check "$(grep -q '40 132' shell.log && echo yes || echo no)" "a window resize reaches the guest's kernel"
kelyfos log --session "$shell_session" > shelllog.txt 2>/dev/null
check "$(grep -q 'shell opened' shelllog.txt && grep -q 'shell closed' shelllog.txt && echo yes || echo no)" \
      "shell.start and shell.end are in the record"
check "$(ls ~/.cache/kelyfos/sessions/"$shell_session"/shell-*.stream >/dev/null 2>&1 && echo no || echo yes)" \
      "and without --transcript nothing of the contents is stored"
check "$(grep -q 'hello-from-the-shell' shelllog.txt && echo no || echo yes)" \
      "the record holds none of what was typed"
killall_kelyfos
cd "$WORK"

# ---------------------------------------------------------------------- 5 ----
say "5. a blocked domain and a ceiling violation both hand back something to paste"
mkdir -p ceiling && cd ceiling
printf '[sandbox]\nimage = "%s"\n\n[resources]\ncpus = 2\n' "$flavor" > kelyfos.toml
ceil="$(kelyfos run --cpus 8 -- true 2>&1)"
sed 's/^/  /' <<<"$ceil" | tail -2
check "$(grep -q '\[ceiling.flag\]' <<<"$ceil" && grep -q 'raise the ceiling in' <<<"$ceil" && echo yes || echo no)" \
      "the ceiling refusal carries its ID and a fix line"

kelyfos run --allow example.com > blocked.log 2>&1 &
for _ in $(seq 1 90); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done
guest_said="$(kelyfos exec 'curl -s http://api.stripe.com/v1/charges' 2>&1)"
sed 's/^/  /' <<<"$guest_said"
check "$(grep -q 'add allow = \["api.stripe.com"\]' <<<"$guest_said" && echo yes || echo no)" \
      "the guest is handed the exact line to add to kelyfos.toml"
check "$(grep -q -- '--allow api.stripe.com' blocked.log && echo yes || echo no)" \
      "and so is the person watching the run"
killall_kelyfos
cd "$WORK"

# ---------------------------------------------------------------------- 6 ----
say "6. a forwarded port reaches a server inside, and only from this machine"
mkdir -p fwd && cd fwd
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml
kelyfos run -p 8080:80 > fwd.log 2>&1 &
for _ in $(seq 1 90); do kelyfos exec "true" >/dev/null 2>&1 && break; sleep 1; done
# The plan wrote this as busybox httpd; this image's busybox has no httpd
# applet, so python3's http.server stands in. What is being checked is the
# forward, not the server: any process listening on the guest's own loopback
# port 80 makes the same point.
kelyfos exec 'mkdir -p /tmp/www; echo served-from-the-guest > /tmp/www/index.html;
  cd /tmp/www; setsid python3 -m http.server 80 --bind 127.0.0.1 >/dev/null 2>&1 &
  sleep 1; echo started' >/dev/null 2>&1
sleep 2
body="$(curl -s --max-time 10 http://127.0.0.1:8080/index.html)"
echo "  $body"
check "$(grep -q served-from-the-guest <<<"$body" && echo yes || echo no)" \
      "curl 127.0.0.1:8080 reaches a server on the guest's own loopback port 80"

lan="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | sed -n 1p)"
echo "  this machine is also $lan"
out="$(curl -s --max-time 5 "http://$lan:8080/index.html" 2>&1; echo "exit=$?")"
check "$(grep -q 'exit=[1-9]' <<<"$out" && echo yes || echo no)" \
      "the same request to this machine's LAN address is refused — the listener is loopback"

fwd_session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
kelyfos log --session "$fwd_session" > fwdlog.txt 2>/dev/null
grep -i forward fwdlog.txt | sed 's/^/  /' | sed -n '1,2p'
check "$(grep -q 'forward' fwdlog.txt && echo yes || echo no)" "forward.accept is in the record"
killall_kelyfos
out="$(curl -s --max-time 5 http://127.0.0.1:8080/ 2>&1; echo "exit=$?")"
check "$(grep -q 'exit=[1-9]' <<<"$out" && echo yes || echo no)" \
      "and after teardown the port is closed"
cd "$WORK"

# ------------------------------------------------------------------ 7 and 8 --
say "7. the history is there, and a rerun reproduces the run rather than the command"
mkdir -p hist && cd hist
printf '[sandbox]\nimage = "%s"\n\n[resources]\ncpus = 2\n' "$flavor" > kelyfos.toml
: > "$NOTIFY_LOG"
kelyfos run --notify -- sh -c 'echo the-failed-run; exit 5' > failed.log 2>&1
failed_code=$?
kelyfos runs -n 3 > runs.txt 2>&1
sed 's/^/  /' runs.txt
hist_session="$(sed -n 2p runs.txt | awk '{print $1}')"
check "$([ "$failed_code" = "5" ] && echo yes || echo no)" "the run exits 5"
check "$(sed -n 2p runs.txt | awk '{print $5}' | grep -qx 5 && echo yes || echo no)" \
      "kelyfos runs lists it with that status"
kelyfos rerun --print "$hist_session" > prov.txt 2>&1
sed 's/^/  /' prov.txt
check "$(grep -q 'the-failed-run' prov.txt && echo yes || echo no)" "the provenance line names the command"
check "$(grep -q "$WORK/hist" prov.txt && echo yes || echo no)" "and the directory"
check "$(grep -q 'frozen when that run started' prov.txt && echo yes || echo no)" "and the frozen policy"
cd "$WORK"
kelyfos rerun "$hist_session" > rerun.log 2>&1
check "$([ "$?" = "5" ] && echo yes || echo no)" "and the rerun reproduces the failure identically"

say "8. --notify fired, and the record verifies with every new event type in it"
sed 's/^/  /' "$NOTIFY_LOG"
check "$(grep -q 'kelyfos: run finished' "$NOTIFY_LOG" && echo yes || echo no)" \
      "a notification fired on completion (mocked notifier)"
check "$(grep -q 'exited 5 after' "$NOTIFY_LOG" && echo yes || echo no)" \
      "carrying the exit status and the duration"

missing=""
for t in shell.start shell.end run.review session.pause session.resume forward.accept; do
  found=no
  for d in ~/.cache/kelyfos/sessions/*/; do
    grep -q "\"type\":\"$t\"" "$d/events.jsonl" 2>/dev/null && { found=yes; break; }
  done
  [ "$found" = yes ] || missing="$missing $t"
done
echo "  new event types not seen:${missing:- none}"
check "$([ -z "$missing" ] && echo yes || echo no)" \
      "every event type this epic added was written by this run"

bad=0
for s in "$shell_session" "$fwd_session" "$hist_session"; do
  kelyfos log --verify --session "$s" > "verify-$s.txt" 2>&1 || bad=$((bad+1))
done
grep -h . verify-*.txt | sed -n '1,3p' | sed 's/^/  /'
check "$([ "$bad" = "0" ] && echo yes || echo no)" \
      "kelyfos log --verify passes on every session this acceptance made"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
