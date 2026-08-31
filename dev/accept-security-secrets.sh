#!/usr/bin/env bash
# KelyfOS — the secret lifecycle, committed as a suite (ST-1.3).
#
#   bash dev/accept-security-secrets.sh
#
# The audit's secret scenarios, machine-checked: the credential never enters
# the guest by any path; it attaches only to terminated TLS with the Host the
# operator bound it to; its reflection in a response comes back scrubbed to
# same-length asterisks; plain HTTP gets it withheld with a reason; and the
# subdomain behaviour is pinned exactly as IA-I1 states it today, so the day
# it changes the suite says so.
#
# Network dependency: like the egress suite, the online battery needs an
# origin that echoes headers (httpbin.org), and skips loudly when the VM host
# cannot reach the internet (D87). The secret-absence battery runs first and
# needs nothing from anywhere.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-secrets

# The credential this suite binds. Fixed rather than random so a failure's
# greps are reproducible; valueless as a credential everywhere but here. The
# -secret flag reads the VALUE from the host environment variable NAMED on
# the flag, so TOK is the variable and SLAB_SECRET_VALUE is its content.
export SLAB_SECRET_VALUE="slab-secret-4f0a9c1e7b2d"
export TOK="$SLAB_SECRET_VALUE"

say "the secret never enters the guest"
aup -allow httpbin.org -secret "TOK@httpbin.org"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi

assert_eq "$(ax "env | grep -c '$SLAB_SECRET_VALUE' || true" 2>/dev/null | tr -d ' ')" "0" \
      "the guest's environment does not carry the secret value"
assert_eq "$(ax "tr '\0' '\n' < /proc/1/environ | grep -c '$SLAB_SECRET_VALUE' || true" 2>/dev/null | tr -d ' ')" "0" \
      "neither does PID 1's environment"
assert_eq "$(ax "grep -r '$SLAB_SECRET_VALUE' /etc /tmp /work 2>/dev/null | wc -l" 2>/dev/null | tr -d ' ')" "0" \
      "and no file in /etc, /tmp or /work holds it"
assert_eq "$(ax 'env | grep -c "^TOK=" || true' 2>/dev/null | tr -d ' ')" "0" \
      "the env var named on the host does not simply reappear in the guest"

say "online battery — attach, withhold, scrub, forge"
if ! slab_net_ok; then
  skip "online battery: the VM host cannot reach httpbin.org right now (network gate; see the suite header)"
  slab_done
  exit 0
fi

# slab_echo — an httpbin.org /headers echo with retries, because the third
# party that hosts it rate-limits bursts and a 429 HTML page would otherwise
# read as a boundary failure. The whole curl argument tail comes through as
# ONE string — the caller's quoting survives — because a split `-H Host:
# evil.com` silently becomes a request to a second URL, which is a test of
# nothing. The suite retries a few times and only then reports what it saw.
slab_echo() { # slab_echo "<url> [extra curl args, quoted as needed]"
  local out="" i
  for i in 1 2 3 4 5 6; do
    out="$(ax "curl -s --max-time 20 $*" 2>/dev/null)"
    case "$out" in *'"Headers"'*) break ;; esac
    sleep 2
  done
  printf '%s' "$out"
}

# Attach on terminated TLS: the origin receives the credential — the record's
# secret.use says so, and the echoed header's presence says the request went
# out carrying it. The guest's own copy is scrubbed before it ever arrives,
# which the next check proves: the raw value can never be seen from here.
auth="$(slab_echo "https://httpbin.org/headers")"
assert_contains "$auth" '"Authorization"' \
      "the credential is attached on a terminated TLS request"
assert_grep_event '"type":\s*"secret.use"' "the record names the use"

# The scrub: the proxy rewrites the credential out of the response on its way
# past, to asterisks of the same length — the response is useful, the secret
# is not in it, and the length is preserved so a truncated value is still a
# visible scrub rather than a silent absence.
scrubbed="$(slab_echo "https://httpbin.org/headers")"
len="${#SLAB_SECRET_VALUE}"
assert_eq "$(grep -c "$SLAB_SECRET_VALUE" <<<"$scrubbed" || true)" "0" \
      "the raw secret appears nowhere in the response"
assert_eq "$(grep -cE "[*]{$len}" <<<"$scrubbed" || true)" "1" \
      "its reflection is same-length asterisks instead"
assert_grep_event '"type":\s*"secret.scrubbed"' "and the scrub itself is in the record"

# Plain HTTP: same origin, no TLS, no credential — withheld with its reason.
plain="$(slab_echo "http://httpbin.org/headers")"
assert_eq "$(grep -c -i "authorization" <<<"$plain" || true)" "0" \
      "no Authorization reaches the origin over plain HTTP"
assert_grep_event 'not_encrypted' "and the record says why: not_encrypted"

# The forgery: the tunnel targets the bound host, the inner request claims
# evil.com. The proxy terminates TLS, reads the lie, and withholds the
# credential — the request still goes to the origin it named in the tunnel,
# without the credential it tried to attract.
forged="$(slab_echo "https://httpbin.org/headers -H 'Host: evil.com'")"
assert_eq "$(grep -c -i "authorization" <<<"$forged" || true)" "0" \
      "a forged Host on a tunnel to the bound host attaches nothing"
assert_grep_event 'host_mismatch' "and the record says why: host_mismatch"

# The subdomain behaviour, pinned exactly as IA-I1 states it today: a
# credential bound to a host is also attached for its subdomains, because the
# host scope is the same dot-anchored match as the allowlist. The attached
# header is visible in the echo (scrubbed, as always) and the record names the
# host it attached for. If this ever changes — bound to the exact host string
# instead — this assertion is what flips, loudly.
sub="$(slab_echo "https://www.httpbin.org/headers")"
assert_contains "$sub" '"Authorization"' \
      "IA-I1 pinned: the credential attaches on www.httpbin.org too"
assert_grep_event '"www.httpbin.org"' "and the record shows the use against the subdomain host"

adown

slab_done
