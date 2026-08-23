#!/usr/bin/env bash
# KelyfOS — `kelyfos shell` under a real terminal (E5-3).
#
#   bash dev/accept-shell.sh
#
# A shell is the one feature that cannot be tested without a terminal: a pty is
# what makes it different from `exec`, and a pipe would prove nothing. So this
# drives the real binary through a pseudo-terminal and checks the things that
# only exist there — a controlling terminal, a window size the guest agrees
# with, resize forwarding, and an exit status that comes back.
#
# It also checks the part that is a promise rather than a mechanism: what the
# record holds. The fact of the shell, always. What was typed and shown, only
# with --transcript (F-D8).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"
PASSES=0 FAILURES=0
SUMMARY=()

cleanup() {
  pkill -f "$BIN/kelyfos run" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

WORK="$(mktemp -d)"
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — kelyfos shell under a real PTY"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"

flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml

say "booting a sandbox to open a shell in"
(timeout 300 kelyfos run > run.log 2>&1 &)
for i in $(seq 1 60); do grep -q "Ctrl-C" run.log 2>/dev/null && break; sleep 1; done
if ! grep -q "Ctrl-C" run.log; then
  fail "the sandbox never came up; nothing below can run"
  tail -5 run.log
  exit 1
fi
session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
echo "  session $session"

cat > drive.py <<'PY'
import fcntl, os, pty, select, signal, struct, subprocess, sys, termios, time

args = sys.argv[1:]
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
p = subprocess.Popen(["kelyfos", "shell"] + args,
                     stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)
out = b""

def drain(seconds):
    global out
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.2)
        if not r:
            continue
        try:
            chunk = os.read(master, 65536)
        except OSError:
            return
        if not chunk:
            return
        out += chunk

drain(4)
os.write(master, b"echo hello-from-the-shell\n"); drain(2)
os.write(master, b"tty; stty size\n"); drain(2)
# A real terminal delivers SIGWINCH itself; this harness's child is not in the
# pty's foreground process group, so it is sent explicitly.
fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 132, 0, 0))
p.send_signal(signal.SIGWINCH); time.sleep(0.5)
os.write(master, b"stty size\n"); drain(2)
os.write(master, b"exit 7\n"); drain(4)

try:
    code = p.wait(timeout=30)
except subprocess.TimeoutExpired:
    p.kill(); code = -1
open("shell.out", "wb").write(out)
print(code)
PY

say "a shell, a terminal, a resize and an exit status"
code="$(timeout 200 python3 drive.py --transcript 2>/dev/null | tail -1)"
sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' shell.out | grep -vE '^\s*$' | sed 's/^/  | /' | head -12

check "$([ "$code" = "7" ] && echo yes || echo no)" "the shell's exit status comes back (7)"
check "$(grep -q 'hello-from-the-shell' shell.out && echo yes || echo no)" "a command ran and its output came back"
check "$(grep -q '/dev/pts/' shell.out && echo yes || echo no)" "it is a real terminal, not a pipe"
check "$(grep -q '24 100' shell.out && echo yes || echo no)" "the guest agrees with the size the host asked for"
check "$(grep -q '40 132' shell.out && echo yes || echo no)" "a resize reaches the guest's kernel"

say "what the record holds"
kelyfos log --session "$session" > log.txt 2>/dev/null
grep -E 'shell' log.txt | sed 's/^/  /'
check "$(grep -q 'shell opened' log.txt && echo yes || echo no)" "the fact of the shell is always recorded"
check "$(grep -q 'shell closed   exit 7' log.txt && echo yes || echo no)" "and how it ended"

stream="$(ls ~/.cache/kelyfos/sessions/"$session"/shell-*.stream 2>/dev/null | head -1)"
check "$([ -n "$stream" ] && echo yes || echo no)" "--transcript wrote the terminal stream"
check "$([ -n "$stream" ] && grep -q 'hello-from-the-shell' "$stream" && echo yes || echo no)" \
      "and the stream holds what was shown"

say "and without --transcript, nothing of the contents is stored"
rm -f ~/.cache/kelyfos/sessions/"$session"/shell-*.stream
code="$(timeout 200 python3 drive.py 2>/dev/null | tail -1)"
check "$([ "$code" = "7" ] && echo yes || echo no)" "the plain shell works the same"
check "$(ls ~/.cache/kelyfos/sessions/"$session"/shell-*.stream >/dev/null 2>&1 && echo no || echo yes)" \
      "no stream file exists"
kelyfos log --session "$session" > log2.txt 2>/dev/null
check "$([ "$(grep -c 'shell opened' log2.txt)" = "2" ] && echo yes || echo no)" \
      "the second shell is in the record too"
check "$(grep -q 'hello-from-the-shell' log2.txt && echo no || echo yes)" \
      "and the record holds none of what was typed"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
