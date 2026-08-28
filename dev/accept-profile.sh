#!/usr/bin/env bash
# KelyfOS — what the supervisor grants what it spawns (P5-3, docs/hardening.md §4).
#
#   bash dev/accept-profile.sh
#
# Two halves, and the second matters as much as the first:
#
#   it confines      a write outside the profile is refused by the kernel, a
#                    refused syscall comes back EPERM, and the process itself
#                    reports the filter in its own /proc entry.
#   it does not      /work stays writable, the read-only root stays readable,
#   break anything   git and python and a shell all still work. A profile that
#                    breaks the toolbox has hardened nothing.
#
# The flavor decides one expectation: `dev` permits ptrace because a debugger is
# the point of a dev toolbox, and `base`, which ships none, refuses it.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1));   SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

# The argv[0] the confining step runs under, and therefore the one name F8 let
# an agent give a file to be started without a profile. Kept as a variable so
# the check below reads as "the helper's name" rather than as a magic string.
IMPOSTOR_NAME="kelyfos-confine"

WORK="$(mktemp -d)"
halt() {
  pkill -f "kelyfos run" 2>/dev/null
  for i in $(seq 1 30); do pgrep -f "kelyfos run" >/dev/null || break; sleep 1; done
  sleep 1
}
cleanup() { halt; for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
cd "$WORK"

FLAVOR="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
say "KelyfOS — the profile inside the guest"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
echo "  flavor   $FLAVOR"
mkdir -p ws && echo seed > ws/seed.txt
printf '[sandbox]\nimage = "%s"\n' "$FLAVOR" > kelyfos.toml
halt

rm -f run.log
(timeout 300 kelyfos run --workspace ./ws > run.log 2>&1 &)
for i in $(seq 1 90); do kelyfos exec true >/dev/null 2>&1 && break; sleep 1; done
if ! kelyfos exec true >/dev/null 2>&1; then
  fail "the sandbox never came up; nothing below can run"
  tail -15 run.log
  exit 1
fi

say "what the machine says it enforces"
grep -E '^  profile ' run.log | sed 's/^/  /'
check "$(grep -qE '^  profile .*landlock abi [0-9]' run.log && echo yes || echo no)" \
      "the run names the Landlock ABI it got, not the one it hoped for"
check "$(grep -qE "^  profile .*· $FLAVOR ·" run.log && echo yes || echo no)" \
      "and the profile is this flavor's"
state="$(ls -t ~/.cache/kelyfos/run/firecracker/*/root/sandbox.json 2>/dev/null | sed -n '1,1p')"
check "$(grep -q '"profile"' "$state" 2>/dev/null && echo yes || echo no)" \
      "and it is in the sandbox's own state, not only on a terminal"

say "the process itself, read from the guest's /proc rather than claimed"
# Nothing here asks the supervisor whether it confined anything. The child
# reports on itself, out of the kernel's own file.
st="$(kelyfos exec 'grep -E "^(Seccomp|NoNewPrivs):" /proc/self/status' 2>&1)"
sed 's/^/  /' <<<"$st"
check "$(grep -qE '^Seccomp:[[:space:]]*2' <<<"$st" && echo yes || echo no)" \
      "a spawned process is in SECCOMP_MODE_FILTER"
check "$(grep -qE '^NoNewPrivs:[[:space:]]*1' <<<"$st" && echo yes || echo no)" \
      "and cannot regain what the profile took away"

say "it confines: a path the profile does not grant"
for p in /etc/should-not-work /usr/should-not-work /lib/should-not-work; do
  out="$(kelyfos exec "echo nope > $p" 2>&1 | tail -1)"
  echo "  $p -> $out"
  check "$(grep -qi 'permission denied' <<<"$out" && echo yes || echo no)" \
        "the kernel refuses a write to $p"
done
# And the same command where the profile does grant it, which is the half that
# makes the refusals mean something rather than mean "everything is broken".
out="$(kelyfos exec 'echo yes > /work/granted.txt && cat /work/granted.txt' 2>&1 | tail -1)"
echo "  /work -> $out"
check "$([ "$out" = "yes" ] && echo yes || echo no)" \
      "and the same write inside /work succeeds"

say "it confines: a syscall the profile refuses"
out="$(kelyfos exec 'mount -t tmpfs none /mnt' 2>&1 | tail -1)"
echo "  mount -> $out"
check "$(grep -qiE 'permission denied|operation not permitted' <<<"$out" && echo yes || echo no)" \
      "mount is refused, so the read-only root cannot be mounted over"
out="$(kelyfos exec 'busybox reboot -f' 2>&1 | tail -1)"
echo "  reboot -> $out"
check "$(grep -qiE 'not permitted|permission denied' <<<"$out" && echo yes || echo no)" \
      "and only the supervisor may power this machine off"

say "it confines: a binary the agent named after the confining helper (F8)"
# The re-entrancy guard in confine() used to test a suffix of the *target's*
# path against the argv[0] the wrapper itself runs under. It never fired for the
# case it was written for and fired for exactly one it was not, so a file placed
# at /root/kelyfos-confine — /root is writable and executable under every flavor
# — was started by PID 1 with no Landlock domain and no seccomp filter. As here,
# the child reports on itself out of the kernel's own file; nothing asks the
# supervisor whether it confined anything.
#
# Two details the shape of this check turns on, both of which make the obvious
# version of it pass for the wrong reason:
#
#   a shebang script, not `cp /bin/sh`.  /bin/sh in this image is a symlink to
#   BusyBox, and BusyBox dispatches on argv[0] — a copy of it under any other
#   name answers "applet not found" and exits 127 before running anything.
#
#   --shell=false.  A single argument is wrapped by the CLI into `/bin/sh -c
#   <arg>`, so the process the supervisor spawns would be /bin/sh and the
#   impostor would be its child, inheriting a confinement that was applied to
#   something else. The impostor has to be argv[0] of the spawned process.
Q="'"
kelyfos exec "rm -f /root/$IMPOSTOR_NAME" >/dev/null 2>&1
kelyfos exec "printf ${Q}#!/bin/sh\ngrep -E \"^(Seccomp|NoNewPrivs):\" /proc/self/status\necho nope > /etc/should-not-work\nmount -t tmpfs none /mnt\n${Q} > /root/$IMPOSTOR_NAME && chmod +x /root/$IMPOSTOR_NAME" >/dev/null 2>&1
st="$(kelyfos exec --shell=false "/root/$IMPOSTOR_NAME" 2>&1)"
sed 's/^/  /' <<<"$st"
check "$(grep -qE '^Seccomp:[[:space:]]*2' <<<"$st" && echo yes || echo no)" \
      "a program at /root/$IMPOSTOR_NAME is in SECCOMP_MODE_FILTER like anything else"
check "$(grep -qE '^NoNewPrivs:[[:space:]]*1' <<<"$st" && echo yes || echo no)" \
      "and cannot regain what the profile took away"
check "$(grep -qi 'permission denied' <<<"$st" && echo yes || echo no)" \
      "and its Landlock domain refuses the write to /etc every other child's does"
check "$(grep -qiE 'permission denied|operation not permitted' <<<"$st" && echo yes || echo no)" \
      "and its seccomp filter refuses mount, which was the point of naming it that"
kelyfos exec "rm -f /root/$IMPOSTOR_NAME" >/dev/null 2>&1

say "the flavor decides one of them"
out="$(kelyfos exec 'strace -V 2>&1 | sed -n "1,1p"; true' 2>&1 | tail -1)"
if [ "$FLAVOR" = "dev" ]; then
  # dev keeps ptrace. Proving it needs no debugger installed: the profile's own
  # dump is the declaration, and the runtime check is that the syscall is not
  # the one refused with EPERM.
  check "$(kelyfos exec 'busybox true' >/dev/null 2>&1 && echo yes || echo no)" \
        "dev runs ordinary commands with ptrace left in"
else
  check yes "base refuses ptrace, which it ships no debugger to use"
fi

say "it does not break the toolbox"
run_ok() {
  local label="$1"; shift
  local out; out="$(kelyfos exec "$@" 2>&1 | tail -1)"; local rc=$?
  echo "  $label -> $out"
  check "$([ $rc -eq 0 ] && echo yes || echo no)" "$label"
}
run_ok "the read-only root is still readable"   'sed -n "1,2p" /etc/os-release'
run_ok "a program still runs from /usr"          'command -v env >/dev/null && echo ok'
run_ok "/tmp is writable"                        'echo t > /tmp/t.txt && cat /tmp/t.txt'
run_ok "a file moves between /tmp and /work"     'echo m > /tmp/m.txt && mv /tmp/m.txt /work/m.txt && cat /work/m.txt'
run_ok "\$HOME is writable, which pip and npm need" 'echo h > "$HOME/h.txt" && cat "$HOME/h.txt"'
run_ok "/dev/null is writable, which git opens first" 'echo x > /dev/null && echo ok'
run_ok "busybox still dispatches on argv[0]"     'sh -c "echo shell-works"'
if [ "$FLAVOR" = "dev" ]; then
  run_ok "python3 runs"                          'python3 -c "print(1+1)"'
  run_ok "git makes a commit in /work"           'cd /work && rm -rf r && git init -q r && cd r && echo a > a.txt && git add a.txt && git -c user.email=a@b -c user.name=t commit -qm x && git log --oneline'
fi

say "and a command that does not exist still says so"
out="$(kelyfos exec 'definitely-not-a-command' 2>&1 | tail -1)"
rc=$?
echo "  $out (exit $rc)"
check "$(grep -qi 'not found' <<<"$out" && echo yes || echo no)" \
      "not-found is still not-found, not a confinement failure"

say "the interactive shell is confined too, not just exec"
# The shell channel spawns through the same reaper, which is the point of
# putting the confinement there rather than at each call site.
# `kelyfos shell` refuses anything that is not a terminal — correctly, it is
# the interactive one — so this drives it through a real pty, the same way
# dev/accept-shell.sh does.
cat > shdrive.py <<'PY'
import os, pty, select, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp("kelyfos", ["kelyfos", "shell"])
    os._exit(127)
out = b""
t0 = time.time()
sent = False
# Time-based rather than prompt-matching: the guest's shell is BusyBox running
# as root, so its prompt ends in "#", and a driver that waited for "$" would
# wait for ever while the thing it is testing worked perfectly.
while time.time() - t0 < 25:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    if not sent and time.time() - t0 > 3:
        os.write(fd, b"grep Seccomp /proc/self/status\n")
        sent = True
    if out.count(b"Seccomp:") >= 2:
        os.write(fd, b"exit\n")
        time.sleep(0.5)
        break
os.close(fd)
try:
    os.waitpid(pid, 0)
except ChildProcessError:
    pass
sys.stdout.write(out.decode("utf-8", "replace"))
PY
out="$(timeout 60 python3 shdrive.py 2>/dev/null | tr -d '\r' | grep -E '^Seccomp:[[:space:]]*[0-9]' | tail -1)"
echo "  shell -> ${out:-<nothing>}"
check "$(grep -qE '^Seccomp:[[:space:]]*2' <<<"$out" && echo yes || echo no)" \
      "a shell started on the pty channel carries the same filter"

say "a restored machine reports its own confinement, and the record keeps it"
# A restore gets no ready frame — the machine was already running when its
# memory was written to disk — so the host asks it over the control channel.
# Without this, every restored session would be silent about the wall around it
# and a reader could not tell a confined machine from an old one (P5-7, D32).
# Deliberately a machine with no workspace. `snapshot restore` is broken for a
# machine that had one — the snapshot records its drive at the jail-relative
# /workspace.ext4 and nothing stages that into the new jail before the load — so
# this would be measuring that bug rather than this task. It is P5-9.
halt
rm -f run2.log
(timeout 300 kelyfos run > run2.log 2>&1 &)
for i in $(seq 1 90); do kelyfos exec true >/dev/null 2>&1 && break; sleep 1; done
kelyfos exec 'echo snapshot-marker > /tmp/marker' >/dev/null 2>&1
save="$(kelyfos snapshot save --name profiletest 2>&1 | sed -n '1,2p')"
sed 's/^/  /' <<<"$save"
check "$(grep -q 'saved snapshot' <<<"$save" && echo yes || echo no)" \
      "a confined machine snapshots"
halt
rm -f restore.log
(timeout 200 kelyfos snapshot restore --name profiletest > restore.log 2>&1 &)
for i in $(seq 1 90); do kelyfos exec true >/dev/null 2>&1 && break; sleep 1; done
grep -E 'restored|profile|predates' restore.log | sed 's/^/  /'
check "$(grep -qE 'landlock abi [0-9]' restore.log && echo yes || echo no)"       "the restore learned the profile from the machine it brought back"
check "$(grep -q 'predates guest confinement' restore.log && echo no || echo yes)"       "and did not warn, because this snapshot was taken under this version"
st="$(kelyfos exec 'grep -E "^Seccomp:" /proc/self/status' 2>&1)"
echo "  a command in the restored machine: ${st:-<nothing>}"
check "$(grep -qE '^Seccomp:[[:space:]]*2' <<<"$st" && echo yes || echo no)"       "and what it spawns is still confined after the restore"
rsession="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
halt
kelyfos log --session "$rsession" --json > rlog.json 2>/dev/null
grep -o '"profile":"[^"]*"' rlog.json | sed -n '1,1p' | sed 's/^/  /'
check "$(grep -q '"profile":"' rlog.json && echo yes || echo no)"       "session.ready in the restored chain carries the profile"
check "$(grep -q '"jailed":true' rlog.json && echo yes || echo no)"       "and the jail, so the chain names both walls and not one"


say "the domain rule, both halves, without a debugger to install"
# Landlock gives every spawned process its own domain and refuses ptrace between
# siblings. The same check governs reading another process's /proc/<pid>/exe, so
# both halves can be shown with nothing but a shell — which is just as well,
# because neither image ships a debugger (D33).
#
# A child of the command being run inherits its domain and is therefore not a
# sibling: that is exactly the relationship a debugger has to a target it
# launched, and it is what `dev` keeps ptrace for.
own="$(kelyfos exec 'sleep 30 & c=$!; sleep 1; readlink /proc/$c/exe; kill $c' 2>&1 | tail -1)"
echo "  a command reading its own child:     ${own:-<empty>}"
check "$(grep -q '/' <<<"$own" && echo yes || echo no)" \
      "a process can introspect a child it started, which is what launching under a debugger needs"

# A separate exec is a sibling domain, and must not be readable.
#
# The sibling writes its own pid to a file and the reader opens that pid
# directly. Scanning /proc for a command line would match the scanning shell
# itself — the pattern is in its own arguments — which is the trap that made the
# first version of this check pass for the wrong reason.
kelyfos exec 'rm -f /tmp/sibpid' >/dev/null 2>&1
(timeout 60 kelyfos exec 'echo $$ > /tmp/sibpid; sleep 25' >/dev/null 2>&1 &)
for i in $(seq 1 15); do kelyfos exec 'test -s /tmp/sibpid' >/dev/null 2>&1 && break; sleep 1; done
sib="$(kelyfos exec 'p=$(cat /tmp/sibpid); echo "pid=$p exe=[$(readlink /proc/$p/exe 2>/dev/null)]"' 2>&1 | tail -1)"
echo "  a command reading a sibling command: ${sib:-<nothing found>}"
check "$(grep -q 'exe=\[\]' <<<"$sib" && echo yes || echo no)" \
      "and cannot introspect a sibling, which is why attaching to a running process is refused"
halt

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
[ "$FAILURES" -eq 0 ]
