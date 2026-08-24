#!/usr/bin/env bash
# KelyfOS — Firecracker under the jailer (P5-1, docs/hardening.md §2).
#
#   bash dev/accept-jail.sh
#
# Every check here reads the host's own /proc rather than believing anything the
# CLI printed. A hardening feature that is verified by asking the thing being
# hardened is not verified.
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
halt() {
  pkill -f "kelyfos run" 2>/dev/null
  for i in $(seq 1 30); do pgrep -f "kelyfos run" >/dev/null || break; sleep 1; done
  sleep 1
}
cleanup() { halt; for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — the VMM inside the jailer"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml
halt

boot() {
  rm -f run.log
  (timeout 300 kelyfos run "$@" > run.log 2>&1 &)
  for i in $(seq 1 90); do kelyfos exec true >/dev/null 2>&1 && break; sleep 1; done
  kelyfos exec true >/dev/null 2>&1
}

say "a sandbox, jailed by default"
if ! boot; then
  fail "the sandbox never came up; nothing below can run"
  tail -10 run.log
  exit 1
fi
vmm="$(pgrep -n firecracker)"
echo "  firecracker pid $vmm"
grep -E 'jail ' run.log | sed 's/^/  /'

say "what the host can see about that process"
# NOT readlink /proc/PID/root: that reports the path as the *process* sees it,
# which after pivot_root is "/" for a jailed process and "/" for an unjailed
# one — the same answer for opposite facts. mountinfo's fourth field is the
# root of the mount as the host sees it, which names the chroot outright.
mroot="$(sudo -n awk '$5=="/"{print $4; exit}' "/proc/$vmm/mountinfo" 2>/dev/null)"
echo "  its root, as the host sees it: ${mroot:-<unreadable>}"
check "$(grep -q "run/firecracker/.*/root" <<<"$mroot" && echo yes || echo no)" \
      "the VMM's root is this sandbox's chroot, not the host's filesystem"

status="$(cat /proc/$vmm/status 2>/dev/null)"
uid="$(awk '/^Uid:/{print $2}' <<<"$status")"
echo "  Uid: $uid (invoking user $(id -u), root would be 0)"
check "$([ "$uid" != "0" ] && echo yes || echo no)" \
      "it is not root, though the jailer that made it was"

nnp="$(awk '/^NoNewPrivs:/{print $2}' <<<"$status")"
check "$([ "$nnp" = "1" ] && echo yes || echo no)" \
      "no_new_privs is set, so it cannot regain what was dropped"

# P5-2's whole claim, read rather than assumed: mode 2 is SECCOMP_MODE_FILTER.
seccomp="$(awk '/^Seccomp:/{print $2}' <<<"$status")"
echo "  Seccomp: $seccomp (2 = filter)"
check "$([ "$seccomp" = "2" ] && echo yes || echo no)" \
      "Firecracker's own seccomp filter is in force, observed not assumed"

say "and what it cannot see"
# Read once, into a variable, so a command that fails is visible as an empty
# listing rather than passing an inverted grep. A check that succeeds when its
# own command errors is worse than no check.
inside="$(sudo -n ls "/proc/$vmm/root/" 2>/dev/null | tr '\n' ' ')"
echo "  its whole filesystem: ${inside:-<unreadable>}"
check "$(grep -q 'rootfs.ext4' <<<"$inside" && echo yes || echo no)" \
      "the listing is the jail's own contents, so the check really read it"
check "$(grep -qE '(^| )(etc|home|usr|var) ' <<<"$inside" && echo no || echo yes)" \
      "and it holds no /etc, /home, /usr or /var — the host is not addressable"

say "the machine still works, which is the other half"
out="$(kelyfos exec 'uname -r' 2>&1 | tail -1)"
echo "  $out"
check "$(grep -qE '^[0-9]+\.' <<<"$out" && echo yes || echo no)" "exec answers from inside the jail"
session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
halt

say "the record says which wall was around it"
kelyfos log --session "$session" --json > log.json 2>/dev/null
grep -o '"jailed":[a-z]*' log.json | sed -n '1,2p' | sed 's/^/  /'
check "$(grep -q '"jailed":true' log.json && echo yes || echo no)" \
      "session.start carries jailed: true"

say "--no-jail says so, every run, and the record agrees"
boot --no-jail >/dev/null 2>&1
grep -E 'no-jail|namespace' run.log | sed 's/^/  /'
check "$(grep -q 'running as you, in your namespace' run.log && echo yes || echo no)" \
      "the terminal is told what is not enforced"
vmm2="$(pgrep -n firecracker)"
mroot2="$(sudo -n awk '$5=="/"{print $4; exit}' "/proc/$vmm2/mountinfo" 2>/dev/null)"
echo "  its root, as the host sees it: ${mroot2:-<unreadable>}"
check "$(grep -q 'run/firecracker/.*/root' <<<"$mroot2" && echo no || echo yes)" \
      "and it really is unjailed — its root is not a chroot"
session2="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
halt
kelyfos log --session "$session2" --json > log2.json 2>/dev/null
check "$(grep -q '"jailed":false' log2.json && echo yes || echo no)" \
      "session.start carries jailed: false — the chain never overstates the wall"

say "a machine that cannot jail is refused, not quietly weakened"
d="$WORK/nopath"; mkdir -p "$d"; ln -sf "$(command -v kelyfos)" "$d/kelyfos"
out="$(cd "$WORK" && PATH="$d:/usr/bin:/bin" "$d/kelyfos" run -- true 2>&1 | tail -3)"
sed 's/^/  /' <<<"$out"
check "$(grep -q '\[jail.no_sudo\]' <<<"$out" && echo yes || echo no)" \
      "the refusal is in the catalog and names itself"
check "$(grep -q 'NOPASSWD' <<<"$out" && echo yes || echo no)" \
      "and its fix line is the sudoers line, ready to paste"

say "snapshot and restore still work inside it"
# With a workspace attached, deliberately. A snapshot records its drives by the
# path written in it, which since P5-1 is chroot-relative, and Firecracker will
# not load one until every backing file is present at that path — so a machine
# that had a workspace could not be restored at all until P5-9 staged the
# captured copy into the new jail *before* the load. Nothing caught it because
# no suite snapshotted a machine with a workspace. This one does.
mkdir -p wsjail && echo seed > wsjail/seed.txt
boot --workspace ./wsjail >/dev/null 2>&1
kelyfos exec "echo survived-the-jail > /tmp/marker" >/dev/null 2>&1
kelyfos exec "echo work-survived > /work/marker" >/dev/null 2>&1
kelyfos snapshot save --name jailtest >/dev/null 2>&1
halt
(timeout 200 kelyfos snapshot restore --name jailtest > restore.log 2>&1 &)
for i in $(seq 1 90); do kelyfos exec true >/dev/null 2>&1 && break; sleep 1; done
grep -qi 'error\|refused' restore.log && sed 's/^/  /' restore.log | head -3
marker="$(kelyfos exec 'cat /tmp/marker' 2>&1 | tail -1)"
echo "  memory:    $marker"
check "$(grep -q 'survived-the-jail' <<<"$marker" && echo yes || echo no)" \
      "a jailed machine snapshots and restores with its full state"
wsmarker="$(kelyfos exec 'cat /work/marker' 2>&1 | tail -1)"
echo "  workspace: $wsmarker"
check "$(grep -q 'work-survived' <<<"$wsmarker" && echo yes || echo no)" \
      "and a machine that had a workspace restores with that disk too"
pkill -f "kelyfos snapshot" 2>/dev/null; sleep 2

say "the cgroup it sits in is the one KelyfOS asked for"
# The other half of this phase's second acceptance item. P5-1 proved the seccomp
# half from /proc and left this one; P5-6 is the task that made it true and this
# is the check that says so.
#
# Read from the process, not from sandbox.json: the state file says where
# KelyfOS meant to put the VMM and /proc/<pid>/cgroup says where the kernel
# actually did, and only the second is evidence. It needs a quota, because
# without one there is no slice to sit in.
halt
boot --cpu-quota 150%
vmm3="$(pgrep -n firecracker)"
grep -E '^  cpu |^  cgroup ' run.log | sed 's/^/  /'
sits="$(awk -F: '$1=="0"{print $3}' "/proc/$vmm3/cgroup" 2>/dev/null)"
state3="$(ls -t ~/.cache/kelyfos/run/firecracker/*/root/sandbox.json 2>/dev/null | head -1)"
asked="$(python3 -c "import json;print(json.load(open('$state3')).get('cgroup_path',''))" 2>/dev/null)"
echo "  asked for: ${asked:-<none>}"
echo "  sits in:   ${sits:-<none>}"
check "$([ -n "$asked" ] && [ -n "$sits" ] && [ "$asked" = "/sys/fs/cgroup$sits" ] && echo yes || echo no)" \
      "the VMM's own cgroup line names the slice KelyfOS created for it"
echo "  cpu.max:   $(cat "/sys/fs/cgroup$sits/cpu.max" 2>/dev/null || echo '<unreadable>')"
check "$(grep -q '^150000 ' "/sys/fs/cgroup$sits/cpu.max" 2>/dev/null && echo yes || echo no)" \
      "and that slice carries the 150% quota this run asked for"
# The quota must not have cost the jail. Both walls, on the same process.
mroot3="$(sudo -n awk '$5=="/"{print $4; exit}' "/proc/$vmm3/mountinfo" 2>/dev/null)"
uid3="$(awk '/^Uid:/{print $2}' "/proc/$vmm3/status" 2>/dev/null)"
echo "  root: ${mroot3:-<unreadable>} · uid: ${uid3:-?}"
check "$(grep -q 'run/firecracker/.*/root' <<<"$mroot3" && [ "$uid3" != "0" ] && echo yes || echo no)" \
      "and a capped machine is still chrooted and still not root"
halt

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
