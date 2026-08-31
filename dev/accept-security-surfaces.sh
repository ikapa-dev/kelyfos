#!/usr/bin/env bash
# KelyfOS — the listening surfaces, committed as a suite (ST-1.6).
#
#   bash dev/accept-security-surfaces.sh
#
# The audit's scenarios for the three places KelyfOS opens a socket or a
# listener, machine-checked:
#
#   - view: the one listening socket the product opens (D60). Token on every
#     route, constant-time compared, loopback-only bind, a Host check that
#     DNS rebinding cannot walk past, GET/HEAD only, and a pinned CSP.
#   - forward: a port carried to the guest over vsock — the firewall must
#     gain nothing while it is live, the listener is loopback by default and
#     says so loudly when told otherwise.
#   - shim: the E2B-compatible surface — a per-process minted token (the help
#     text's e2b_kelyfos is the documented-by-drift one, IA-L1(a): do not
#     assert it), 401 without it, loopback bind.
#
# No network beyond loopback.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-surfaces

say "view — token, host check, method check, binding, CSP"
aup
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
ax "echo ok" >/dev/null 2>&1   # an event or two, so the report has a body

# The view server: backgrounded, its URL carrying the minted token.
( "$BIN/kelyfos" view -session "$AUP_ID" > "$SLAB_WORK/view.log" 2>&1 & echo $! > "$SLAB_WORK/view.pid" )
for i in $(seq 1 60); do grep -aq "127.0.0.1:" "$SLAB_WORK/view.log" 2>/dev/null && break; sleep 0.5; done
view_url="$(grep -aoE 'http://127\.0\.0\.1:[0-9]+/\?token=[0-9a-f]+' "$SLAB_WORK/view.log" | head -1)"
if [ -z "$view_url" ]; then
  fail "the view server started and printed its tokenized URL"
  tail -4 "$SLAB_WORK/view.log" | sed 's/^/  | /'
  adown; slab_done; exit 1
fi
pass "the view server started and printed its tokenized URL"
view_addr="${view_url%/*}"
vport="${view_addr##*:}"

assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$vport/")" "401" \
      "no token on any route is a 401"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$vport/?token=wrong")" "401" \
      "a wrong token is a 401"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "$view_url")" "200" \
      "the minted token opens the report"

# The Host check: the defence against DNS rebinding. Any Host that is not the
# address actually bound is refused — including ones that RESOLVE to
# loopback, which is the whole point.
for hostile in "evil.com" "127.0.0.1.nip.io" "127.0.0.1." "[::1]"; do
  assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $hostile" "$view_url")" "403" \
        "a Host header of $hostile is a 403, even when it resolves to loopback"
done
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$view_url")" "405" \
      "POST is not a method the report serves (405)"

csp="$(curl -s -D - -o /dev/null "$view_url" | grep -i '^content-security-policy:')"
assert_contains "$csp" "default-src 'none'" "the CSP pins default-src 'none'"
assert_contains "$csp" "frame-ancestors 'none'" "and frame-ancestors 'none'"

# The token exists in the server's memory and its URL — not in the process
# list, where any user on the box could read it.
ps_line="$(ps -ww -p "$(cat "$SLAB_WORK/view.pid")" -o args= 2>/dev/null)"
assert_eq "$(grep -c "${view_url##*token=}" <<<"$ps_line" || true)" "0" \
      "the token never appears in the server's argv"
kill "$(cat "$SLAB_WORK/view.pid")" 2>/dev/null

say "forward — vsock transport, loopback bind, firewall untouched"
# The guest serves a port; the host forwards to it. The firewall is marked
# before the forward exists and compared while it is live.
nft_mark
( "$BIN/kelyfos" run -image dev -p 8080:80 > "$SLAB_WORK/fwd.log" 2>&1 & echo $! > "$SLAB_WORK/fwd.pid" )
for i in $(seq 1 150); do grep -aq "^sandbox=" "$SLAB_WORK/fwd.log" 2>/dev/null && break; sleep 0.2; done
fwd_id="$(sed -n 's/^sandbox=\([0-9a-f]*\)$/\1/p' "$SLAB_WORK/fwd.log" | head -1)"
if [ -z "$fwd_id" ]; then
  fail "the forwarded sandbox booted"
  tail -4 "$SLAB_WORK/fwd.log" | sed 's/^/  | /'
  adown; slab_done; exit 1
fi
pass "the forwarded sandbox booted"
# ax targets the harness's slot; the forward sandbox was booted directly, so
# point the slot at it before exec'ing into "the" sandbox.
AUP_ID="$fwd_id"
# The established way to leave a service running in the guest after exec
# returns: setsid detaches it from the exec's process group, so the
# supervisor's cleanup does not take it with the command that started it.
ax 'mkdir -p /tmp/www; echo hello-from-forward > /tmp/www/index.html; cd /tmp/www; setsid python3 -m http.server 80 --bind 0.0.0.0 >/dev/null 2>&1 & sleep 1; echo started' >/dev/null 2>&1
sleep 3

listener="$(ss -tlnp 2>/dev/null | grep ":8080" | head -1)"
assert_contains "$listener" "127.0.0.1:8080" "the host listener binds loopback only"
assert_nft_unchanged "the nft ruleset is byte-identical while a forward is live"
assert_eq "$(curl -s --max-time 5 http://127.0.0.1:8080/index.html 2>/dev/null)" "hello-from-forward" \
      "the host reaches the guest's service through the forward"

# The reverse direction is not a thing: the guest cannot open connections back
# to the host through the forward — the transport is vsock, the firewall gains
# no path, and the guest has no route to this host's own ports.
rev="$(ax 'timeout 3 python3 -c "
import socket
try:
    s = socket.create_connection((\"169.254.92.41\", 8080), timeout=2)
    print(\"CONNECTED\")
except Exception:
    print(\"BLOCKED\")
" 2>/dev/null || echo BLOCKED' 2>/dev/null)"
check "$(grep -q "CONNECTED" <<<"$rev" && echo no || echo yes)" \
      "the guest cannot reach back to the host's listener through the forward"

kill -INT "$(cat "$SLAB_WORK/fwd.pid")" 2>/dev/null
for i in $(seq 1 40); do kill -0 "$(cat "$SLAB_WORK/fwd.pid")" 2>/dev/null || break; sleep 0.5; done
scope_kill_kelyfos run

say "forward — an exposed bind says so, every time"
expose="$("$BIN/kelyfos" run -image dev -p 8080:80 -p-bind 0.0.0.0 -- sleep 2 2>&1)"
assert_contains "$expose" "0.0.0.0" "the exposure warning names the bind it was asked for"
assert_contains "$expose" "expos" "and says what exposing means"

say "shim — a per-process token, loopback, and nothing else"
( "$BIN/kelyfos" shim > "$SLAB_WORK/shim.log" 2>&1 & echo $! > "$SLAB_WORK/shim.pid" )
for i in $(seq 1 60); do grep -aq "127.0.0.1:" "$SLAB_WORK/shim.log" 2>/dev/null && break; sleep 0.5; done
shim_port="$(grep -aoE '127\.0\.0\.1:[0-9]+' "$SLAB_WORK/shim.log" | head -1 | cut -d: -f2)"
shim_token="$(grep -aoE '[0-9a-f]{32,}' "$SLAB_WORK/shim.log" | head -1)"
if [ -z "$shim_port" ]; then
  fail "the shim started and printed its address"
  tail -4 "$SLAB_WORK/shim.log" | sed 's/^/  | /'
  adown; slab_done; exit 1
fi
pass "the shim started and printed its address"

assert_eq "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$shim_port/sandboxes")" "401" \
      "an unauthenticated shim request is a 401"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer e2b_kelyfos" "http://127.0.0.1:$shim_port/sandboxes")" "401" \
      "the help text's static key is (still) rejected — IA-L1(a) is a doc defect, not a token"
check "$([ -n "$shim_token" ] && echo yes || echo no)" "the shim minted a per-process token and printed it once"
assert_eq "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $shim_token" "http://127.0.0.1:$shim_port/sandboxes")" "200" \
      "the minted token authenticates"
kill "$(cat "$SLAB_WORK/shim.pid")" 2>/dev/null

adown

slab_done
