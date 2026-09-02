#!/usr/bin/env bash
# KelyfOS — the resource caps are a claim until something tries to exceed each
# one and the host watches it fail (E1-8).
#
#   bash dev/prove-caps.sh
#
# Every figure below is measured on the host, from counters the kernel keeps
# about the Firecracker process and the TAP attached to it. The guest is never
# asked how much it used: a guest that could report its own consumption could
# report a flattering number, which is the same reasoning that puts the caps
# host-side (F-D2).
#
# Run this on bare KVM. Decision D15 makes a bare-KVM x86_64 runner the
# environment that *defines* whether a number is met; under nested
# virtualisation the guest cannot generate enough demand to make a CPU cap
# visible at all, which is precisely the hole this script exists to close.
set -uo pipefail

ARCH="${ARCH:-$(uname -m | sed -e 's/^arm64$/aarch64/' -e 's/^amd64$/x86_64/')}"
KELYFOS="${KELYFOS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/kelyfos}"
# This run gets its own KELYFOS_CACHE and tears down only the machines under
# it. The lines that used to be here -- a `pkill -f` on a kelyfos process name
# and `for p in $(pgrep firecracker); do kill "$p"; done` -- were host-wide
# questions answered with a kill, and on a machine running more than one
# worktree they took a peer's microVMs down with them (D79).
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"/dev/scope.sh
scope_init prove-caps

RUN_ROOT="$KELYFOS_CACHE/run"

# The run directory has moved twice. The jailer put a sandbox's state at
# <run>/firecracker/<id>/root/sandbox.json rather than <run>/<id>/ (P5-1), and
# F19 moved it up one more level, to <run>/firecracker/<id>/sandbox.json, so
# that the chroot the VMM is dropped into cannot reach the host's own record of
# the machine.
#
# Resolve it instead of spelling any one layout, so a script that reads it keeps
# working across the change rather than quietly measuring nothing (P5-6). That
# was the stated intent last time and it still did not survive the next move,
# because only two of the three spellings were listed — which is the failure
# this comment exists to prevent, so: newest first, and add rather than replace.
statefile() { ls -t "$RUN_ROOT"/*/"$1"/sandbox.json "$RUN_ROOT"/*/"$1"/root/sandbox.json "$RUN_ROOT/$1/sandbox.json" 2>/dev/null | sed -n '1,1p'; }

WORK="$(mktemp -d)"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

cleanup() {
  scope_teardown
  rm -rf "$WORK"
}
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

# start <dir> <extra kelyfos run flags...>  — boots a sandbox and sets SB / VMPID.
#
# kelyfos is backgrounded directly rather than inside a subshell, so RUNPID is
# the CLI's own pid: signalling a wrapper subshell would leave the sandbox
# running and every later case would be measuring the wrong machine.
start() {
  local dir="$1"; shift
  mkdir -p "$dir"
  pushd "$dir" >/dev/null || return 1
  "$KELYFOS" run --arch "$ARCH" --image dev "$@" > run.log 2>&1 &
  RUNPID=$!
  popd >/dev/null || return 1
  for _ in $(seq 1 400); do
    grep -q "ready in" "$dir/run.log" 2>/dev/null && break
    sleep 0.25
  done
  if ! grep -q "ready in" "$dir/run.log" 2>/dev/null; then
    echo "      the sandbox never became ready:"; sed 's/^/      /' "$dir/run.log"
    return 1
  fi
  SB="$(awk '/^sandbox /{print $2; exit}' "$dir/run.log")"
  VMPID="$(python3 -c "import json;print(json.load(open('$(statefile "$SB")'))['pid'])" 2>/dev/null)"
  if [ -z "${VMPID:-}" ]; then
    echo "      could not read the sandbox's pid for $SB under $RUN_ROOT"
    return 1
  fi
  echo "      sandbox $SB (firecracker pid $VMPID)"
}

stop() {
  kill -INT "$RUNPID" 2>/dev/null
  for _ in $(seq 1 60); do
    kill -0 "$RUNPID" 2>/dev/null || break
    sleep 0.5
  done
  kill -9 "$RUNPID" 2>/dev/null
  wait "$RUNPID" 2>/dev/null
}

# cpu_seconds <pid> — utime+stime from /proc, in seconds. The comm field can
# contain spaces and parentheses, so fields are counted from the last ')'.
cpu_seconds() {
  python3 - "$1" <<'PY'
import sys
pid = sys.argv[1]
with open(f"/proc/{pid}/stat") as f:
    blob = f.read()
fields = blob[blob.rindex(")") + 1:].split()
print((int(fields[11]) + int(fields[12])) / 100.0)
PY
}

io_bytes() { # io_bytes <pid> <read_bytes|write_bytes>
  awk -v k="$2:" '$1==k {print $2}' "/proc/$1/io" 2>/dev/null || echo 0
}

tap_bytes() { # tap_bytes <tap> <rx_bytes|tx_bytes>
  cat "/sys/class/net/$1/statistics/$2" 2>/dev/null || echo 0
}

# rates <before> <after> <seconds> <cap-bytes-per-second> -- prints "gross steady",
# both in millions of bytes per second.
#
# Steady state discounts the opening burst, and the discount is not a fudge: a
# Firecracker token bucket starts full, and because it only advances its own
# last_update when it has to replenish, a device idle beforehand is handed about
# two bucket-fulls before the limit begins to bite (docs/resources.md). At every
# cap this script uses the bucket is exactly one second's worth, so the burst is
# two seconds of traffic. Both figures are printed; the assertion is on the one
# that describes the limit rather than the first two seconds of it.
rates() {
  python3 -c '
import sys
before, after, secs, cap = (float(x) for x in sys.argv[1:5])
moved = after - before
gross = moved / 1e6 / max(secs, 1)
steady = max(moved - 2 * cap, 0) / 1e6 / max(secs, 1)
print(f"{gross:.2f} {steady:.2f}")
' "$1" "$2" "$3" "$4"
}

say "KelyfOS resource caps — enforcement proof (E1-8)"
echo "  arch        $ARCH"
echo "  kelyfos     $("$KELYFOS" version 2>/dev/null | sed -n '1,1p')"
echo "  host        $(uname -srm), $(nproc) cpus"
# Worth printing rather than assuming, because it decides whether any of the
# numbers below mean anything (D15). x86 advertises a hypervisor flag; aarch64
# does not, so the flag alone would report "bare metal" from inside a VM.
if command -v systemd-detect-virt >/dev/null 2>&1; then
  VIRT="$(systemd-detect-virt || true)"
else
  VIRT="$(grep -qE '^flags.* hypervisor' /proc/cpuinfo 2>/dev/null && echo "vm (x86 hypervisor flag)" || echo unknown)"
fi
echo "  virtualised $VIRT"
if [ "$VIRT" != "none" ]; then
  echo "              this host is itself a guest, so the CPU figures below are"
  echo "              informational: a nested guest cannot generate the demand a"
  echo "              CPU cap needs to be visible at all (D15)."
fi

# ---------------------------------------------------------------- CPU quota --
# The proof is a comparison, not a single number: the same workload under three
# quotas on the same machine. A cap that is not below available demand proves
# nothing, which is why 4 vCPUs are given 4 stressors.
cpu_case() { # cpu_case <label> <expected cores' worth> [extra flags...]
  local label="$1" expect="$2"; shift 2
  local dir="$WORK/cpu-$label"
  start "$dir" --cpus 4 "$@" || { fail "cpu $label: the sandbox never became ready"; return; }
  local before after wall used
  before="$(cpu_seconds "$VMPID")"
  local t0=$SECONDS
  "$KELYFOS" exec --sandbox "$SB" "stress-ng --cpu 4 --timeout 10s" >/dev/null 2>&1
  wall=$(( SECONDS - t0 )); [ "$wall" -gt 0 ] || wall=1
  after="$(cpu_seconds "$VMPID")"
  used="$(python3 -c "print(f'{$after - $before:.2f}')")"
  local cores; cores="$(python3 -c "print(f'{($after - $before)/$wall:.2f}')")"
  printf '        %-10s %5ss of host CPU over %ss = %s core(s) busy (expected ~%s)\n' \
    "$label" "$used" "$wall" "$cores" "$expect"
  stop
  CPU_MEASURED="$cores"
}

say "1. CPU quota — cpu.max on the VM's own cgroup"
cpu_case uncapped "4.0"
CPU_UNCAPPED="$CPU_MEASURED"
cpu_case 50% "0.5" --cpu-quota 50%
CPU_50="$CPU_MEASURED"
cpu_case 150% "1.5" --cpu-quota 150%
CPU_150="$CPU_MEASURED"

# A quota holds if the machine stayed under it, with room for the sampling
# interval. It is only a *proof* if the uncapped run went meaningfully higher —
# otherwise the workload, not the cap, was the limit.
if python3 -c "import sys; sys.exit(0 if $CPU_50 <= 0.60 else 1)"; then
  pass "50% quota held: $CPU_50 cores' worth against a 0.5 ceiling"
else
  fail "50% quota exceeded: $CPU_50 cores' worth against a 0.5 ceiling"
fi
if python3 -c "import sys; sys.exit(0 if $CPU_150 <= 1.70 else 1)"; then
  pass "150% quota held: $CPU_150 cores' worth against a 1.5 ceiling"
else
  fail "150% quota exceeded: $CPU_150 cores' worth against a 1.5 ceiling"
fi
# A cap that was never approached proves nothing. On bare metal that is a
# failure; on a nested host it is the expected result and the reason D15 exists,
# so it is reported as skipped rather than dressed up as either outcome.
if python3 -c "import sys; sys.exit(0 if $CPU_UNCAPPED > $CPU_150 * 1.3 else 1)"; then
  pass "the comparison is meaningful: uncapped reached $CPU_UNCAPPED cores' worth"
elif [ "$VIRT" != "none" ]; then
  skip "the 150% quota is untested here: uncapped only reached $CPU_UNCAPPED cores' worth on a nested host (D15)"
else
  fail "uncapped only reached $CPU_UNCAPPED cores' worth — this machine cannot generate enough demand to test a cap"
fi

# ------------------------------------------------------------------- memory --
say "2. Memory — the cap is VM hardware; the proof is that hitting it is legible"
dir="$WORK/mem"
if start "$dir" --mem 256M; then
  # Not stress-ng, for this one cap, and the reason is worth stating: its vm
  # stressor is built to *survive* memory pressure. It catches a failed mapping,
  # adapts, and reports a successful run either way — measured here, "--vm 4
  # --vm-bytes 100M" produced zero kills on aarch64 while claiming to pass, and
  # "--vm 1 --vm-bytes 400M" produced three on aarch64 and none at all on
  # x86_64, where the overcommit heuristic turned the single large mapping away
  # at the door rather than letting it be killed. A test whose instrument is
  # designed to avoid the outcome being tested is not a test.
  #
  # A plain allocator loop has no such opinions: each megabyte passes the
  # heuristic on its own, they accumulate, and the kernel does what the kernel
  # does. python3 is in the dev flavor for the same reason stress-ng is.
  out="$("$KELYFOS" exec --sandbox "$SB" \
      'python3 -c "b=[bytearray(1048576) for _ in range(512)]; print(len(b))"' 2>&1)"
  sleep 2
  stop
  if "$KELYFOS" log --session "$SB" 2>/dev/null | grep -q "OOM-killed"; then
    "$KELYFOS" log --session "$SB" | grep "OOM-killed" | sed -n '1,3p' | sed 's/^/        /'
    pass "the guest OOM-killer fired and the host recorded it by name"
  else
    # Print what the stressor said. A memory test that fails silently is a test
    # that will be re-run rather than read.
    echo "$out" | tail -6 | sed 's/^/        /'
    fail "no resource.oom event was recorded"
  fi
else
  fail "memory: the sandbox never became ready"
fi

# --------------------------------------------------------------------- disk --
say "3. Disk bandwidth — Firecracker's token bucket on the block devices"
dir="$WORK/disk"
mkdir -p "$dir/ws"
printf '[resources]\ndisk_mbps = 20\n' > "$dir/kelyfos.toml"
if start "$dir" --mem 512M --workspace "$dir/ws" --disk 1G; then
  before="$(io_bytes "$VMPID" write_bytes)"
  t0=$SECONDS
  "$KELYFOS" exec --sandbox "$SB" \
    "dd if=/dev/zero of=/work/blob bs=1M count=400 conv=fsync" >/dev/null 2>&1
  wall=$(( SECONDS - t0 )); [ "$wall" -gt 0 ] || wall=1
  after="$(io_bytes "$VMPID" write_bytes)"
  stop
  read -r mbps steady <<<"$(rates "$before" "$after" "$wall" 20000000)"
  echo "        $(python3 -c "print(f'{($after-$before)/1e6:.1f}')") MB written in ${wall}s"
  echo "        gross $mbps MB/s . steady $steady MB/s . cap 20 MB/s"
  if python3 -c "import sys; sys.exit(0 if $steady <= 22 else 1)"; then
    pass "disk_mbps = 20 held: $steady MB/s steady state, from /proc/<pid>/io"
  else
    fail "disk_mbps = 20 exceeded: $steady MB/s steady state (gross $mbps)"
  fi
else
  fail "disk: the sandbox never became ready"
fi

# ------------------------------------------------------------------ network --
say "4. Network bandwidth — Firecracker's token bucket on the NIC"
# The local test server's address, as a literal. It used to be a name mapped
# to 127.0.0.1 in /etc/hosts, and since v1.1 the proxy refuses an allowlisted
# *name* whose resolved address is loopback, link-local or private (the DNS
# rebinding fix, internal/egress/dial.go, F14) — so the guest's download got
# nothing and this step measured 0 Mbps. A literal address never goes through
# a resolver, so there is nothing for DNS to have hijacked and the check does
# not apply; and it cannot be the loopback address, because the guest's own
# NO_PROXY excludes 127.0.0.1 from the proxy. The host's primary address is
# what remains: private on a runner or in a VM, and reached only through the
# proxy, which is the path being measured.
NETHOST="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i+1); exit }}')"
[ -n "$NETHOST" ] || NETHOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [ -z "$NETHOST" ] || ! sudo -n true 2>/dev/null; then
  skip "network: needs sudo to serve on port 80, and a primary address to serve on"
else
  mkdir -p "$WORK/web"
  # 100 MB, so the two-second opening burst is a tenth of the transfer rather
  # than a quarter of it. A short download measures the burst, not the cap.
  head -c 100000000 /dev/urandom > "$WORK/web/blob.bin"
  # Anything already listening on port 80 would answer instead, and quietly
  # serve a different file -- which is exactly how a bandwidth number goes wrong
  # without looking wrong.
  sudo pkill -f "http.server 80" 2>/dev/null
  sleep 1
  ( cd "$WORK/web" && sudo nohup python3 -m http.server 80 --bind "$NETHOST" >/dev/null 2>&1 & )
  sleep 2
  NETSERVER=yes
  served="$(curl -s -o /dev/null -w '%{size_download}' "http://$NETHOST/blob.bin" || echo 0)"
  if [ "$served" != "100000000" ]; then
    skip "network: the test server returned $served bytes, not the 100 MB file this case needs"
    NETSERVER=no
  fi
  dir="$WORK/net"
  mkdir -p "$dir"
  printf '[resources]\nnet_mbps_rx = 20\n' > "$dir/kelyfos.toml"
  if [ "${NETSERVER:-no}" = "no" ]; then
    :
  elif start "$dir" --mem 512M --allow "$NETHOST"; then
    tap="$(python3 -c "import json;print(json.load(open('$(statefile "$SB")'))['tap'])")"
    before="$(tap_bytes "$tap" tx_bytes)"
    t0=$SECONDS
    "$KELYFOS" exec --sandbox "$SB" \
      "curl -s -o /dev/null http://$NETHOST/blob.bin" >/dev/null 2>&1
    wall=$(( SECONDS - t0 )); [ "$wall" -gt 0 ] || wall=1
    after="$(tap_bytes "$tap" tx_bytes)"
    stop
    # 20 Mbps is 2,500,000 bytes a second, which is the size of the bucket.
    read -r gross steady <<<"$(rates "$before" "$after" "$wall" 2500000)"
    grossbits="$(python3 -c "print(f'{$gross*8:.2f}')")"
    steadybits="$(python3 -c "print(f'{$steady*8:.2f}')")"
    echo "        $(python3 -c "print(f'{($after-$before)/1e6:.1f}')") MB into the guest in ${wall}s"
    echo "        gross $grossbits Mbps . steady $steadybits Mbps . cap 20 Mbps"
    if python3 -c "import sys; sys.exit(0 if 0 < $steadybits <= 22 else 1)"; then
      pass "net_mbps_rx = 20 held: $steadybits Mbps steady state, from the TAP's own counters"
    else
      fail "net_mbps_rx = 20 not demonstrated: $steadybits Mbps steady state (gross $grossbits)"
    fi
  else
    fail "network: the sandbox never became ready"
  fi
  sudo pkill -f "http.server 80" 2>/dev/null
fi

# ------------------------------------------------------------------ scratch --
say "5. Scratch — size= on the tmpfs behind the overlay"
dir="$WORK/scratch"
mkdir -p "$dir"
printf '[resources]\nscratch = "64M"\n' > "$dir/kelyfos.toml"
if start "$dir" --mem 512M; then
  out="$("$KELYFOS" exec --sandbox "$SB" "dd if=/dev/zero of=/tmp/blob bs=1M count=200" 2>&1)"
  stop
  echo "$out" | grep -E "records out|No space" | sed 's/^/        /'
  if echo "$out" | grep -q "No space left on device"; then
    pass "scratch = 64M held: writes outside /work stopped at the cap with ENOSPC"
  else
    fail "scratch = 64M did not stop a 200 MiB write"
  fi
else
  fail "scratch: the sandbox never became ready"
fi

# ------------------------------------------------------------- time budgets --
say "6. Time budget — a host timer, and an exit status that says so"
dir="$WORK/time"
mkdir -p "$dir"
t0=$SECONDS
( cd "$dir" && "$KELYFOS" run --arch "$ARCH" --image dev --max-runtime 10s \
    -- sh -c 'sleep 300' > "$dir/run.log" 2>&1 )
code=$?
wall=$(( SECONDS - t0 )); [ "$wall" -gt 0 ] || wall=1
grep -E "budget of" "$dir/run.log" | sed 's/^/        /'
if [ "$code" -eq 124 ] && [ "$wall" -lt 30 ]; then
  pass "max_runtime = 10s fired after ${wall}s and exited $code"
else
  fail "max_runtime = 10s: exit $code after ${wall}s (wanted 124, promptly)"
fi

# ------------------------------------------------------------------ verdict --
say "Verdict"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPS"
[ "$FAILURES" -eq 0 ]
