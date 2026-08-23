#!/usr/bin/env bash
# KelyfOS — `kelyfos watch` under a real terminal.
#
#   bash dev/accept-watch.sh
#
# The unit tests render the model's view and read the string. That covers what
# the view says and nothing about the terminal: whether the alt screen is
# entered and left, whether a keypress is seen, whether the process exits
# cleanly when told to. Under Bubble Tea v2 those are the parts that moved —
# the alt screen became a field of the view and a keypress became a different
# message type — so they are exactly what a migration has to re-prove (F-D41).
#
# So this drives the real binary through a pseudo-terminal, which is the only
# way any of it happens at all: with no tty, Bubble Tea does not render.
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

say "KelyfOS — kelyfos watch under a real PTY"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# A session to watch. A real one, from a real machine, so the view has the
# events it renders rather than a fixture that agrees with itself.
say "recording a session to watch"
# Whichever flavor this machine has built; the view does not care which.
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
if ! timeout 120 kelyfos run --image "$flavor" -- sh -c 'kelyfos exec "echo watched" >/dev/null' > run.log 2>&1; then
  fail "could not record a session; nothing below can run"
  cat run.log
  exit 1
fi
session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
echo "  session $session"

cat > drive.py <<'PY'
"""Run `kelyfos watch` on a real pseudo-terminal and read what it writes."""
import os, pty, select, subprocess, sys, time

session = sys.argv[1]
master, slave = pty.openpty()
# A terminal it can render into. Bubble Tea asks the tty for its size, and a
# 0x0 terminal renders nothing at all.
import fcntl, struct, termios
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

p = subprocess.Popen(["kelyfos", "watch", "--session", session],
                     stdin=slave, stdout=slave, stderr=slave, close_fds=True)
os.close(slave)

out = b""
deadline = time.time() + 12
while time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.4)
    if r:
        try:
            chunk = os.read(master, 65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    if b"watched" in out or b"sandbox" in out:
        break

time.sleep(0.5)
os.write(master, b"q")          # the quit key, as a real keypress
try:
    code = p.wait(timeout=12)
except subprocess.TimeoutExpired:
    p.kill()
    code = -1

# Drain whatever it wrote on the way out, which is where the alt screen is left.
deadline = time.time() + 2
while time.time() < deadline:
    r, _, _ = select.select([master], [], [], 0.2)
    if not r:
        break
    try:
        chunk = os.read(master, 65536)
    except OSError:
        break
    if not chunk:
        break
    out += chunk

with open("watch.out", "wb") as fh:
    fh.write(out)
print("exit", code)
PY

say "driving it"
result="$(timeout 60 python3 drive.py "$session")"
echo "  $result"
code="${result##* }"

say "what a real terminal saw"
size="$(wc -c < watch.out)"
echo "  $size bytes"
python3 - <<'PY'
raw = open("watch.out", "rb").read()
import re
text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", raw)
text = re.sub(rb"\x1b[()][A-Z0-9]", b"", text)
print("  " + "\n  ".join(
    l for l in text.decode("utf-8", "replace").splitlines() if l.strip())[:600])
PY

check "$([ "$code" = "0" ] && echo yes || echo no)" "q quits, and the process exits 0"
check "$(grep -q $'\e\[?1049h' watch.out && echo yes || echo no)" "it entered the alt screen"
check "$(grep -q $'\e\[?1049l' watch.out && echo yes || echo no)" "and left it again on the way out"
check "$(python3 -c "
import re,sys
raw=open('watch.out','rb').read()
t=re.sub(rb'\x1b\[[0-9;?]*[A-Za-z]',b'',raw).decode('utf-8','replace')
sys.exit(0 if 'sandbox' in t else 1)" && echo yes || echo no)" "it rendered the session header"
check "$([ "$size" -gt 200 ] && echo yes || echo no)" "it wrote a screen rather than nothing"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
