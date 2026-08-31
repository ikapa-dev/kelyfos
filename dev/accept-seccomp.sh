#!/usr/bin/env bash
# KelyfOS — the host syscall filter (P5-2, docs/hardening.md §3).
#
#   bash dev/accept-seccomp.sh
#
# Three claims, in the order the task makes them.
#
#   which filter   — the one compiled into the pinned Firecracker binary,
#                    because the VMM's own /proc/<pid>/cmdline carries neither
#                    --no-seccomp nor --seccomp-filter.
#   that it is on  — every thread of the VMM reports SECCOMP_MODE_FILTER, and a
#                    VMM started without one is refused rather than run.
#   what it permits— the program is pulled back out of the kernel and read, and
#                    what it allows is diffed against the committed record.
#
# Nothing here asks the CLI whether it did the right thing. The kernel is asked
# instead, which is the only witness that was there.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"
ARCH="${ARCH:-$(uname -m)}"
EXPECT="$REPO/dev/expect/host-seccomp-$ARCH.txt"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1));   SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

WORK="$(mktemp -d)"
# This run gets its own KELYFOS_CACHE and tears down only the machines under
# it. The lines that used to be here -- `pkill -f "kelyfos run"` and
# `for p in $(pgrep firecracker); do kill "$p"; done` -- were host-wide
# questions answered with a kill, and on a machine running more than one
# worktree they took a peer's microVMs down with them (D79).
source "$REPO/dev/scope.sh"
scope_init accept-seccomp

halt() {
  scope_kill_kelyfos run
  scope_wait_kelyfos_gone 30 run
  sleep 1
}
cleanup() { scope_teardown; rm -rf "$WORK"; }
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — the filter around the VMM"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
echo "  arch     $ARCH"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml
halt

boot() {
  rm -f run.log
  (timeout 300 kelyfos run "$@" > run.log 2>&1 &)
  for i in $(seq 1 90); do kelyfos exec true >/dev/null 2>&1 && break; sleep 1; done
  kelyfos exec true >/dev/null 2>&1
}

# The probe is built here rather than by `make`, because it is the acceptance's
# instrument and nothing else calls it.
say "the instrument"
if ! (cd "$REPO" && go build -o "$BIN/seccomp-probe" ./dev/seccomp-probe) 2>&1 | sed 's/^/  /'; then
  fail "seccomp-probe did not build; nothing below can run"
  exit 1
fi
echo "  built $BIN/seccomp-probe"

say "a sandbox, and the VMM it started"
if ! boot; then
  fail "the sandbox never came up; nothing below can run"
  tail -10 run.log
  exit 1
fi
vmm="$(scope_newest_pid)"
echo "  firecracker pid $vmm"

# --- which filter ---------------------------------------------------------
say "which filter — read off the VMM's own command line"
cmdline="$(tr '\0' ' ' < "/proc/$vmm/cmdline" 2>/dev/null)"
echo "  $cmdline"
check "$(grep -q -- '--no-seccomp' <<<"$cmdline" && echo no || echo yes)" \
      "the VMM was not started with --no-seccomp"
check "$(grep -q -- '--seccomp-filter' <<<"$cmdline" && echo no || echo yes)" \
      "nor with --seccomp-filter, so the filter is the one built into the binary"
# An absence check passes just as well on an empty string, so prove the read.
check "$(grep -q 'api-sock' <<<"$cmdline" && echo yes || echo no)" \
      "and the command line really was read, not silently empty"

fcver="$(firecracker --version 2>/dev/null | sed -n '1,1p')"
echo "  $fcver"
check "$(grep -q "$(grep -E '^FIRECRACKER_VERSION' "$REPO/versions.mk" | sed 's/.*= *//')" <<<"$fcver" && echo yes || echo no)" \
      "and that binary is the version versions.mk pins"

# --- that it is on --------------------------------------------------------
say "that it is on — every thread, not the process"
threads=0 filtered=0
for t in /proc/$vmm/task/*; do
  threads=$((threads+1))
  mode="$(awk '/^Seccomp:/{print $2}' "$t/status" 2>/dev/null)"
  echo "  $(cat "$t/comm" 2>/dev/null) Seccomp=$mode"
  [ "$mode" = "2" ] && filtered=$((filtered+1))
done
check "$([ "$threads" -gt 0 ] && [ "$threads" = "$filtered" ] && echo yes || echo no)" \
      "all $filtered of $threads VMM threads are in SECCOMP_MODE_FILTER"

say "and the run says so, in the terminal and in its own state"
grep -E 'seccomp' run.log | sed 's/^/  /'
check "$(grep -q 'seccomp     filter mode' run.log && echo yes || echo no)" \
      "the run printed the mode it observed"
state="$(ls -t "$KELYFOS_CACHE"/run/firecracker/*/sandbox.json "$KELYFOS_CACHE"/run/firecracker/*/root/sandbox.json 2>/dev/null | sed -n '1,1p')"
echo "  $(grep -o '"seccomp[^,]*' "$state" 2>/dev/null | tr '\n' ' ')"
check "$(grep -qE '"seccomp": ?"filter"' "$state" 2>/dev/null && echo yes || echo no)" \
      "and wrote it into the sandbox's own state rather than only to a terminal"

# --- what it permits ------------------------------------------------------
say "what it permits — the program, read back out of the kernel"
if ! sudo -n true 2>/dev/null; then
  skip "no passwordless sudo, so the installed program cannot be dumped"
else
  sudo -n "$BIN/seccomp-probe" -pid "$vmm" -format record > got.txt 2>probe.err
  rc=$?
  if [ $rc -ne 0 ]; then
    fail "the filter could not be read: $(sed -n '1,2p' probe.err)"
  else
    grep -E '^filter|instructions|sha256|unlisted-syscall|foreign-arch|allowed |conditional ' got.txt | sed 's/^/  /'
    check "$(grep -q 'unlisted-syscall TRAP' got.txt && echo yes || echo no)" \
          "a syscall on no list is trapped, so it is an allowlist and not a log"
    check "$(grep -q 'unlisted-syscall ALLOW' got.txt && echo no || echo yes)" \
          "and the default is not to allow, which an empty filter would report"
    check "$(grep -q 'complete false' got.txt && echo no || echo yes)" \
          "every syscall number was decided; none exhausted the walk"

    if [ ! -f "$EXPECT" ]; then
      skip "no committed record for $ARCH yet — $(basename "$EXPECT") is missing"
      echo "  what this machine reports has been left in $WORK/got.txt"
      cp got.txt "$REPO/dev/expect/host-seccomp-$ARCH.txt.observed" 2>/dev/null && \
        echo "  and copied to dev/expect/host-seccomp-$ARCH.txt.observed"
    elif diff -u "$EXPECT" got.txt > diff.txt; then
      pass "what it permits is exactly what dev/expect/$(basename "$EXPECT") records"
    else
      fail "the filter has changed since it was recorded"
      sed -n '1,40p' diff.txt | sed 's/^/  /'
    fi
  fi
fi
halt

# --- the negative control -------------------------------------------------
# A check that only ever passes proves nothing. This starts a VMM that really
# has no filter — a wrapper on PATH that appends --no-seccomp to the flags
# Firecracker is given — and the run must refuse rather than come up.
#
# It has to be the unjailed path: the jailer copies its --exec-file into the
# chroot and execs it there, where a shell wrapper's interpreter does not exist.
# The filter is the VMM's own either way, so the check being proved is the same
# one.
say "a VMM with no filter is refused, not quietly accepted"
shim="$WORK/shim"; mkdir -p "$shim"
real="$(command -v firecracker)"
cat > "$shim/firecracker" <<EOF
#!/bin/sh
exec "$real" "\$@" --no-seccomp
EOF
chmod +x "$shim/firecracker"
out="$(cd "$WORK" && PATH="$shim:$PATH" timeout 200 kelyfos run --no-jail -- true 2>&1 | tail -6)"
sed 's/^/  /' <<<"$out"
check "$(grep -q '\[seccomp.not_in_force\]' <<<"$out" && echo yes || echo no)" \
      "the refusal is in the catalog and names itself"
check "$(grep -q 'install-firecracker' <<<"$out" && echo yes || echo no)" \
      "and its fix line names the script that installs a binary with the filter in it"
check "$(grep -qE 'Seccomp: 0' <<<"$out" && echo yes || echo no)" \
      "and it says which thread reported what, rather than only that something was wrong"
halt
# This run's own machines only. `pgrep -c firecracker` counts every
# Firecracker on the host, so a peer worktree's sandbox made this assertion
# fail for a reason that had nothing to do with the refusal being checked --
# F18's shape, which S20 fixed the same way in dev/demo-team.sh.
left="$(scope_live_pids | wc -l)"
echo "  firecracker processes left behind: $left"
check "$([ "$left" = "0" ] && echo yes || echo no)" \
      "and the machine it refused was torn down rather than left running"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
[ "$FAILURES" -eq 0 ]
