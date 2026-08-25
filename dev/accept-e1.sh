#!/usr/bin/env bash
# KelyfOS — Epic E1's acceptance test, run as written.
#
#   bash dev/accept-e1.sh
#
# The seven steps below are PLAN-FEATURES.html's E1 acceptance list, in its
# order and with its numbers. They are here as a script rather than as a
# transcript so the next person can re-run them rather than believe them.
#
# Binding numbers come from the bare-KVM reference (D15). Steps 2 and 4 are
# measurements and mean nothing on a nested host; the rest are behaviour and
# mean the same everywhere.
set -uo pipefail

ARCH="${ARCH:-$(uname -m | sed -e 's/^arm64$/aarch64/' -e 's/^amd64$/x86_64/')}"
KELYFOS="${KELYFOS:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bin/kelyfos}"
RUN_ROOT="${HOME}/.cache/kelyfos/run"

# The run directory moved when the jailer landed (P5-1): a sandbox's state now
# lives at <run>/firecracker/<id>/root/sandbox.json rather than <run>/<id>/.
# Resolve it instead of spelling either layout, so a script that reads it keeps
# working across the change rather than quietly measuring nothing (P5-6).
statefile() { ls -t "$RUN_ROOT"/*/"$1"/root/sandbox.json "$RUN_ROOT/$1/sandbox.json" 2>/dev/null | sed -n '1,1p'; }

WORK="$(mktemp -d)"
NETHOST="kelyfos-accept.test"
PASSES=0 FAILURES=0 SKIPS=0
SUMMARY=()

cleanup() {
  pkill -f "[b]in/kelyfos run" 2>/dev/null
  sleep 1
  for p in $(pgrep -x firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  sudo pkill -f "[h]ttp[.]server" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIPS=$((SKIPS+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }

if command -v systemd-detect-virt >/dev/null 2>&1; then VIRT="$(systemd-detect-virt || true)"; else VIRT=unknown; fi

PROJ="$WORK/project"
mkdir -p "$PROJ/ws"
echo "seed" > "$PROJ/ws/seed.txt"

# ------------------------------------------------------------------ step 1 --
# The acceptance list's own toml. One deviation, and it is arithmetic rather
# than convenience: steps 2-4 cannot fit inside the list's own 60-second budget.
# Filling a 1 GiB device through one vCPU capped at half a core takes about 51
# seconds on its own, and a 10 Mbps download long enough to measure takes
# another 16 — the budget expires in the middle of step 3 and takes steps 4
# onward with it, which is what a first run of this script did.
#
# So it is run as two sandboxes under the same policy: steps 2-4 with the budget
# raised, and step 5 with the file exactly as the list writes it, to watch the
# 60 seconds fire. Every key, every cap and every assertion is unchanged.
cat > "$PROJ/kelyfos.toml" <<TOML
[resources]
cpu_quota   = "50%"
net_mbps_rx = 10
max_runtime = "600s"
TOML

step "1. kelyfos run --image dev --cpus 1 --mem 512M --disk 1G, with the acceptance toml"
echo "        $(tr '\n' ' ' < "$PROJ/kelyfos.toml")"
echo "        (max_runtime is 600s here and 60s in step 5; see the note in this script)"

# The download in step 4 needs somewhere to download from, and it has to be
# ready before the sandbox that will fetch from it.
NETSERVER=no
if sudo -n true 2>/dev/null; then
  grep -q "$NETHOST" /etc/hosts || echo "127.0.0.1 $NETHOST" | sudo tee -a /etc/hosts >/dev/null
  mkdir -p "$WORK/web"
  # 20 MB: about sixteen seconds at the 10 Mbps this policy sets, which is long
  # enough for the opening burst to be a small share of the transfer and short
  # enough to be a step in a test rather than a coffee break.
  head -c 20000000 /dev/urandom > "$WORK/web/blob.bin"
  sudo pkill -f "[h]ttp[.]server" 2>/dev/null
  sleep 1
  ( cd "$WORK/web" && sudo nohup python3 -m http.server 80 --bind 127.0.0.1 >/dev/null 2>&1 & )
  sleep 2
  [ "$(curl -s -o /dev/null -w '%{size_download}' http://127.0.0.1/blob.bin || echo 0)" = "20000000" ] && NETSERVER=yes
fi

pushd "$PROJ" >/dev/null || exit 1
"$KELYFOS" run --arch "$ARCH" --image dev --cpus 1 --mem 512M --disk 1G \
  --workspace "$PROJ/ws" --allow "$NETHOST" > "$PROJ/run.log" 2>&1 &
RUNPID=$!
popd >/dev/null || exit 1
STARTED=$SECONDS
for _ in $(seq 1 400); do grep -q "ready in" "$PROJ/run.log" 2>/dev/null && break; sleep 0.25; done
if ! grep -q "ready in" "$PROJ/run.log" 2>/dev/null; then
  sed 's/^/        /' "$PROJ/run.log"
  fail "the sandbox never became ready"
  printf '%s\n' "${SUMMARY[@]}"; exit 1
fi
SB="$(awk '/^sandbox /{print $2; exit}' "$PROJ/run.log")"
VMPID="$(python3 -c "import json;print(json.load(open('$(statefile "$SB")'))['pid'])")"
TAP="$(python3 -c "import json;print(json.load(open('$(statefile "$SB")')).get('tap',''))")"
grep -E "^  (cpu|scratch|net limit|egress|workspace)" "$PROJ/run.log" | sed 's/^/        /'
pass "the sandbox booted under the committed policy (sandbox $SB)"

# The acceptance list asks for host *cgroup* stats, so that is what is read when
# there is a cgroup to read — which there is here, because cpu_quota created
# one. /proc is the fallback for a sandbox without a quota, and measures the
# same process.
CGROUP="$(python3 -c "import json;print(json.load(open('$(statefile "$SB")')).get('cgroup_path',''))")"
[ -n "$CGROUP" ] && echo "        cgroup: $CGROUP" && echo "        cpu.max: $(cat "$CGROUP/cpu.max" 2>/dev/null)"

cpu_seconds() {
  if [ -n "$CGROUP" ] && [ -r "$CGROUP/cpu.stat" ]; then
    awk '/^usage_usec/{printf "%.2f\n", $2/1000000}' "$CGROUP/cpu.stat"
    return
  fi
  python3 -c '
import sys
with open(f"/proc/{sys.argv[1]}/stat") as f: blob = f.read()
fields = blob[blob.rindex(")") + 1:].split()
print((int(fields[11]) + int(fields[12])) / 100.0)
' "$1"
}

# ------------------------------------------------------------------ step 2 --
step "2. in-guest stress-ng --cpu 4, against a 50% quota"
before="$(cpu_seconds "$VMPID")"; t0=$SECONDS
"$KELYFOS" exec --sandbox "$SB" "stress-ng --cpu 4 --timeout 10s" >/dev/null 2>&1
wall=$(( SECONDS - t0 )); [ "$wall" -gt 0 ] || wall=1
after="$(cpu_seconds "$VMPID")"
cores="$(python3 -c "print(f'{($after - $before)/$wall:.2f}')")"
echo "        $(python3 -c "print(f'{$after - $before:.2f}')")s of host CPU over ${wall}s = $cores core(s) busy"
if python3 -c "import sys; sys.exit(0 if $cores <= 0.60 else 1)"; then
  pass "host cgroup accounting shows $cores core(s) consumed against a 0.5 ceiling"
else
  fail "the quota did not hold: $cores core(s) consumed against a 0.5 ceiling"
fi

# ------------------------------------------------------------------ step 3 --
step "3. dd into /work until ENOSPC at 1 GiB, and into scratch until ENOSPC at the default"
out="$("$KELYFOS" exec --sandbox "$SB" "dd if=/dev/zero of=/work/fill bs=1M count=2000 2>&1" 2>&1)"
echo "$out" | tail -3 | sed 's/^/        /'
if echo "$out" | grep -q "No space left on device"; then
  pass "/work filled to its 1 GiB device size and stopped with ENOSPC"
else
  fail "/work did not stop at the device size"
fi
df="$("$KELYFOS" exec --sandbox "$SB" "df -m / | tail -1")"
echo "        overlay: $df"
out="$("$KELYFOS" exec --sandbox "$SB" "dd if=/dev/zero of=/tmp/fill bs=1M count=400 2>&1" 2>&1)"
echo "$out" | tail -3 | sed 's/^/        /'
got="$(echo "$out" | awk '/records out/{print $1}' | cut -d+ -f1)"
if echo "$out" | grep -q "No space left on device" && [ "${got:-0}" -ge 200 ] && [ "${got:-0}" -le 260 ]; then
  pass "scratch stopped at ${got} MiB — the unset default of 50% of the 512M guest RAM"
elif echo "$out" | grep -q "No space left on device"; then
  fail "scratch stopped at ${got} MiB, not the ~256 MiB the default implies"
else
  fail "scratch did not stop at all"
fi

# ------------------------------------------------------------------ step 4 --
step "4. download from an allowlisted local server, against net_mbps_rx = 10"
if [ "$NETSERVER" = "no" ]; then
  skip "no local test server (needs sudo to bind port 80)"
elif [ -z "$TAP" ]; then
  skip "the sandbox has no TAP to measure"
else
  before="$(cat "/sys/class/net/$TAP/statistics/tx_bytes")"; t0=$SECONDS
  "$KELYFOS" exec --sandbox "$SB" "curl -s -o /dev/null http://$NETHOST/blob.bin" >/dev/null 2>&1
  wall=$(( SECONDS - t0 )); [ "$wall" -gt 0 ] || wall=1
  after="$(cat "/sys/class/net/$TAP/statistics/tx_bytes")"
  read -r gross steady <<<"$(python3 -c '
import sys
before, after, secs, cap = (float(x) for x in sys.argv[1:5])
moved = after - before
print(f"{moved*8/1e6/max(secs,1):.2f} {max(moved-2*cap,0)*8/1e6/max(secs,1):.2f}")
' "$before" "$after" "$wall" 1250000)"
  echo "        $(python3 -c "print(f'{($after-$before)/1e6:.1f}')") MB in ${wall}s: gross $gross Mbps, steady $steady Mbps"
  if python3 -c "import sys; sys.exit(0 if 0 < $steady <= 11 else 1)"; then
    pass "observed throughput $steady Mbps against a 10 Mbps cap"
  else
    fail "observed throughput $steady Mbps against a 10 Mbps cap"
  fi
fi

# ------------------------------------------------------------------ step 5 --
# Steps 2-4 are done with; the long-budget sandbox has served its purpose.
kill -INT "$RUNPID" 2>/dev/null
wait "$RUNPID" 2>/dev/null

# Step 3 filled /work to a gigabyte, and the teardown above faithfully synced
# that gigabyte back to the host. Left in place it would make the next
# sandbox's --disk 1G too small for its own workspace, and step 5 would fail
# for a reason that has nothing to do with time budgets.
rm -f "$PROJ/ws/fill"

step "5. let the 60 s budget fire"
sed -i 's/max_runtime = "600s"/max_runtime = "60s"/' "$PROJ/kelyfos.toml"
echo "        now with the list's own file: $(tr '\n' ' ' < "$PROJ/kelyfos.toml")"
pushd "$PROJ" >/dev/null || exit 1
"$KELYFOS" run --arch "$ARCH" --image dev --cpus 1 --mem 512M --disk 1G \
  --workspace "$PROJ/ws" --allow "$NETHOST" -- sh -c 'sleep 600' > "$PROJ/timeout.log" 2>&1
code=$?
popd >/dev/null || exit 1
SB="$(awk '/^sandbox /{print $2; exit}' "$PROJ/timeout.log")"
if [ -z "$SB" ]; then
  echo "        the sandbox never started:"; sed 's/^/        /' "$PROJ/timeout.log"
fi
sed -n '/budget of/p' "$PROJ/timeout.log" | sed 's/^/        /'
grep -E "workspace written back" "$PROJ/timeout.log" | sed 's/^/        /'
if [ "$code" -eq 124 ]; then
  pass "the run exited 124, which is what a timeout means"
else
  fail "the run exited $code, not 124"
fi
if grep -q "workspace written back" "$PROJ/timeout.log" && [ -f "$PROJ/ws/seed.txt" ]; then
  pass "the workspace was synced back during the timeout teardown"
else
  fail "the workspace was not synced back"
fi
# Not "run/ is empty": the jailer's path scheme keeps a firecracker/ level
# under it that teardown is not meant to remove, so emptiness stopped being the
# question at P5-1. What must be gone is the sandbox — its state and its
# sockets, wherever they were (P5-6).
LEFT="$(find "$RUN_ROOT" \( -name sandbox.json -o -name 'v.sock*' -o -name 'fc.sock' \) 2>/dev/null | tr '\n' ' ')"
if [ -z "$LEFT" ]; then
  pass "teardown left no sandbox behind"
else
  fail "teardown left $LEFT behind"
fi

# ------------------------------------------------------------------ step 6 --
step "6. the record: verify, resource.timeout, resource.summary, and the export"
if [ -z "$SB" ]; then
  fail "step 5 left no session to inspect"
fi
"$KELYFOS" log --session "$SB" | tail -4 | sed 's/^/        /'
if "$KELYFOS" log --session "$SB" --verify 2>&1 | tee /dev/stderr | grep -q "chain intact"; then
  pass "kelyfos log --verify passes"
else
  fail "kelyfos log --verify does not pass"
fi
for want in resource.timeout resource.summary; do
  if [ -n "$SB" ] && grep -q "\"$want\"" "$HOME/.cache/kelyfos/sessions/$SB/events.jsonl" 2>/dev/null; then
    pass "the log contains $want"
  else
    fail "the log has no $want"
  fi
done
"$KELYFOS" log --session "$SB" --export "$WORK/report.html" >/dev/null 2>&1
if grep -q "usage receipt" "$WORK/report.html"; then
  sed -n '/usage receipt/,/<\/tr>/p' "$WORK/report.html" | sed 's/<[^>]*>//g' | grep -v '^ *$' | sed 's/^/        /'
  pass "kelyfos log --export renders the usage receipt"
else
  fail "the export has no usage receipt"
fi

# ------------------------------------------------------------------ step 7 --
step "7. a flag that exceeds a toml ceiling refuses at boot, naming the ceiling"
CEIL="$WORK/ceiling"
mkdir -p "$CEIL"
printf '[resources]\ncpus = 2\n' > "$CEIL/kelyfos.toml"
out="$( cd "$CEIL" && "$KELYFOS" run --arch "$ARCH" --image dev --cpus 8 2>&1 )"
echo "$out" | sed 's/^/        /'
if echo "$out" | grep -q "exceeds the ceiling cpus = 2"; then
  pass "--cpus 8 refused, naming the ceiling and the file it came from"
else
  fail "--cpus 8 was not refused"
fi

# ----------------------------------------------------------------- verdict --
step "Verdict — Epic E1 acceptance"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed, %d skipped   (host: %s, arch: %s)\n' \
  "$PASSES" "$FAILURES" "$SKIPS" "$VIRT" "$ARCH"
[ "$FAILURES" -eq 0 ]
