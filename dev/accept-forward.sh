#!/usr/bin/env bash
# KelyfOS — inbound port forwarding, and the firewall it does not touch (E5-5).
#
#   bash dev/accept-forward.sh
#
# The feature is one sentence — a host port reaches a server inside the sandbox
# — and the reason it is allowed to exist is another: no packet crosses the TAP,
# so the nftables ruleset that makes the network egress-only is untouched
# (F-D7). A test that only proved the first sentence would be testing the easy
# half. So this captures the ruleset before and during a forward and diffs it,
# and checks the guest's own interface counters for inbound traffic that would
# have to be there if a packet had actually crossed.
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
cleanup() {
  pkill -f "kelyfos run" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — inbound port forwarding over vsock"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"

printf '[sandbox]\nimage = "%s"\n' "$flavor" > kelyfos.toml

# The ruleset with the per-sandbox parts blanked out. Each sandbox gets its own
# table name, interface, address and proxy port, so two runs are never textually
# equal; what has to be equal is the *shape*, and that is what this compares.
rules() {
  { sudo -n nft list ruleset 2>/dev/null || nft list ruleset 2>/dev/null; } |
    sed -e 's/kelyfos_[0-9a-f]\{8\}/kelyfos_SANDBOX/g' \
        -e 's/kelyfos[0-9a-f]\{8\}/kelyfosSANDBOX/g' \
        -e 's/169\.254\.[0-9]*\.[0-9]*/GUEST_IP/g' \
        -e 's/dport [0-9]*/dport PORT/g' \
        -e 's/packets [0-9]* bytes [0-9]*/COUNTERS/g'
}

boot() {
  rm -f run.log
  (timeout 400 kelyfos run --allow example.com "$@" > run.log 2>&1 &)
  for i in $(seq 1 90); do grep -q "Ctrl-C" run.log 2>/dev/null && break; sleep 1; done
  grep -q "Ctrl-C" run.log
}

halt() {
  pkill -f "kelyfos run" 2>/dev/null
  for i in $(seq 1 30); do pgrep -f "kelyfos run" >/dev/null || break; sleep 1; done
  sleep 2
}

say "a networked sandbox with no forwards, for the ruleset to be compared against"
if ! boot; then
  fail "the sandbox never came up; nothing below can run"
  tail -20 run.log
  exit 1
fi
rules > plain.rules
echo "  $(wc -l < plain.rules) lines of ruleset"
halt

say "a sandbox with two forwarded ports and a network"
if ! boot -p 18080:8080 -p 18081:8081; then
  fail "the sandbox never came up; nothing below can run"
  tail -20 run.log
  exit 1
fi
grep -E 'forward ' run.log | sed 's/^/  /'
check "$(grep -q '127.0.0.1:18080 -> guest 8080' run.log && echo yes || echo no)" \
      "the run says what it bound and where it goes"
ss -ltn 2>/dev/null | grep -E '1808[01]' | sed 's/^/  /'
check "$(ss -ltn 2>/dev/null | grep -E '1808[01]' | grep -qE '^\S+\s+\S+\s+\S+\s+127\.0\.0\.1:' && echo yes || echo no)" \
      "and it bound loopback, not every address"

say "nothing is listening in there yet"
out="$(curl -s --max-time 5 http://127.0.0.1:18080/ 2>&1; echo "exit=$?")"
echo "  $out"
check "$(grep -q 'exit=[1-9]' <<<"$out" && echo yes || echo no)" \
      "a connection to a port with no server behind it fails"
sleep 1
grep -A1 'forward.closed' run.log | sed 's/^/  /'
check "$(grep -q '\[forward.closed\]' run.log && echo yes || echo no)" \
      "and the host is told which port had nothing on it, with the fix"

say "start a server inside the sandbox and ask again"
kelyfos exec 'mkdir -p /tmp/www; echo "hello from inside the sandbox" > /tmp/www/index.html;
  cd /tmp/www; setsid python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
  sleep 1; echo started' >/dev/null 2>&1
sleep 3
body="$(curl -s --max-time 10 http://127.0.0.1:18080/index.html)"
echo "  $body"
check "$(grep -q 'hello from inside the sandbox' <<<"$body" && echo yes || echo no)" \
      "the host reaches a server that only listens on the guest's loopback"

say "the firewall is the same as it was"
rules > forwarded.rules
if diff -u plain.rules forwarded.rules > rules.diff; then
  pass "the ruleset is identical with two forwards and with none"
else
  fail "the ruleset changed when ports were forwarded"
  sed -n '1,25p' rules.diff | sed 's/^/    /'
fi
# Belt and braces, because an identical ruleset would also be the answer if
# neither run had any rules at all: the rules that make the sandbox egress-only
# are there, and nothing anywhere mentions a forwarded port.
check "$(grep -q 'jump kelyfos_guest_in' forwarded.rules && echo yes || echo no)" \
      "the egress-only chains are in force while ports are forwarded"
check "$(grep -qE '18080|18081|dnat|redirect' forwarded.rules && echo no || echo yes)" \
      "no rule mentions a forwarded port, and there is no dnat anywhere"

say "and no packet crossed the TAP"
# The guest's own interface counters. A forwarded connection is created inside
# the machine, on loopback, so eth0 sees nothing of it. This is the difference
# between "the rules did not change" and "there was nothing for them to stop".
kelyfos exec 'cat /proc/net/dev | sed -n "1,4p"' > netdev.txt 2>&1
sed 's/^/  /' netdev.txt
lo_rx="$(awk -F'[: ]+' '/lo:/ {print $3}' netdev.txt)"
echo "  loopback received $lo_rx bytes"
check "$([ "${lo_rx:-0}" -gt 100 ] && echo yes || echo no)" \
      "the guest's loopback carried it"

say "the record has one line per connection, not per packet"
session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
kelyfos log --session "$session" > log.txt 2>/dev/null
grep -i 'forward' log.txt | sed 's/^/  /'
check "$(grep -qi 'forward' log.txt && echo yes || echo no)" \
      "forward.accept is in the flight recorder"
check "$(grep -c 'forward' log.txt | awk '{print ($1 >= 2) ? "yes" : "no"}')" \
      "both the refused connection and the carried one"

say "teardown closes the listeners"
halt
out="$(curl -s --max-time 5 http://127.0.0.1:18080/ 2>&1; echo "exit=$?")"
check "$(grep -q 'exit=[1-9]' <<<"$out" && echo yes || echo no)" \
      "the forwarded port stops answering when the sandbox goes"

say "and it works on a sandbox with no network at all"
# The shape a forward is most useful for, and the one that was broken until the
# E5 exit found it: with no --allow there is no NIC and no kernel `ip=`
# argument, so the guest's own loopback stayed DOWN and nothing could bind it
# (F-D55). A forward is not a network feature and must not need one.
halt
rm -f run.log
(timeout 300 kelyfos run -p 18083:8080 > run.log 2>&1 &)
for i in $(seq 1 90); do grep -q "Ctrl-C" run.log 2>/dev/null && break; sleep 1; done
if ! grep -q "Ctrl-C" run.log; then
  fail "the no-network sandbox never came up"
  tail -5 run.log
else
  kelyfos exec 'ip addr show lo 2>&1 | sed -n 1p' | sed 's/^/  /'
  kelyfos exec 'mkdir -p /tmp/www; echo no-network-needed > /tmp/www/index.html;
    cd /tmp/www; setsid python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
    sleep 1; echo started' >/dev/null 2>&1
  sleep 2
  body="$(curl -s --max-time 10 http://127.0.0.1:18083/index.html)"
  echo "  $body"
  check "$(grep -q 'no-network-needed' <<<"$body" && echo yes || echo no)" \
        "a forward reaches a server in a sandbox that has no network interface"
  # Captured first rather than piped into grep -q: under pipefail, grep closing
  # the pipe early sends SIGPIPE to its producer and fails the pipeline.
  lo_state="$(kelyfos exec 'ip addr show lo' 2>&1)"
  check "$(grep -q 'UP' <<<"$lo_state" && echo yes || echo no)" \
        "because the supervisor brings the guest's loopback up whether or not there is a NIC"
  halt
fi

say "a LAN exposure is loud, every time"
if ! boot -p 18082:8080 --p-bind 0.0.0.0; then
  fail "the sandbox with --p-bind never came up"
  tail -10 run.log
else
  grep -E 'exposes this sandbox|There is no authentication' run.log | sed 's/^/  /'
  check "$(grep -q 'exposes this sandbox' run.log && echo yes || echo no)" \
        "--p-bind 0.0.0.0 says what it did, in the run's own output"
  check "$(grep -q 'no authentication' run.log && echo yes || echo no)" \
        "and says there is nothing in front of it"
  ss -ltn 2>/dev/null | grep 18082 | sed 's/^/  /'
  check "$(ss -ltn 2>/dev/null | grep -qE '(\*|0\.0\.0\.0|\[::\]):18082' && echo yes || echo no)" \
        "and the listener really is on every address"
  halt
fi

say "what the file and the flags refuse"
mkdir -p badpolicy
printf '[sandbox]\nimage = "%s"\n\n[[forward]]\nhost = 8080\n' "$flavor" > badpolicy/kelyfos.toml
out="$(cd badpolicy && kelyfos run -- true 2>&1)"
sed 's/^/  /' <<<"$out" | tail -2
check "$(grep -q 'no guest port' <<<"$out" && echo yes || echo no)" \
      "half a [[forward]] pair is refused, naming the line"
out="$(cd "$WORK" && kelyfos run -p 8080 -- true 2>&1)"
check "$(grep -q 'host:guest' <<<"$out" && echo yes || echo no)" \
      "-p without a colon says what the shape is"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
