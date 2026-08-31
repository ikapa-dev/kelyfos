#!/usr/bin/env bash
# KelyfOS — the egress boundary, committed as a suite (ST-1.2).
#
#   bash dev/accept-security-egress.sh
#
# The independent audit (2026-08-31) proved these scenarios by hand against
# live sandboxes; this file is that proof, machine-checked, so it stops being
# something one auditor did once and becomes something every run re-earns.
# The claims under test are the boundary's headline ones:
#
#   - with no --allow there is NO network interface at all — off, not filtered;
#   - the allowlist is exact-host plus dot-anchored subdomains, and the
#     suffix trap (notexample.com beside example.com) does not pass;
#   - ports are 80/443 globally and no key, flag or trick widens them;
#   - CONNECT, absolute-URI and origin-form are all decided on the same
#     string, so the parser's shape cannot become the policy's gap;
#   - the post-resolution address check refuses the metadata and RFC1918
#     addresses a DNS hijack would point at — reached through nip.io, which
#     maps <ip>.nip.io back to <ip>, under an allowlist that lets the name
#     reach the resolver at all, because the allowlist is checked first;
#   - a foreign peer — another sandbox's guest, or any VM-side process — is
#     dropped silently by the nft rules rather than answered.
#
# Refusals are asserted with raw sockets, not curl: a 403 that answers a
# CONNECT is invisible to curl's %{http_code}, which reports 000 — the code a
# naive suite would misread as a network failure rather than the wall working.
#
# Network dependency, decided explicitly rather than discovered in a red run
# (D87): the offline battery runs everywhere, always. The online battery needs
# example.com and nip.io — a third party's wildcard resolver — and is skipped
# loudly, by name, when the VM host cannot reach the open internet at suite
# start, so a network outage reads as SKIP, never as a regression and never as
# a silent pass.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-egress

say "offline battery — a sandbox with no --allow"
aup
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi

# The guest's own view of its network. lo is the only interface a sandbox
# without --allow has — the interface is absent, not firewalled.
guest_links="$(ax 'ip -o link show' 2>/dev/null | tr -d ' ')"
assert_eq "$(grep -c ':lo' <<<"$guest_links")" "1" "the guest has a loopback interface"
check "$(grep -qE '(eth|enp|tap)' <<<"$guest_links" && echo no || echo yes)" \
      "a sandbox with no --allow has no network interface at all"
assert_eq "$(ax 'ip route show table main 2>/dev/null | wc -l' 2>/dev/null | tr -d ' ')" "0" \
      "its route table is empty — nothing to route with"
assert_eq "$(ax 'test -f /etc/resolv.conf && echo present || echo absent' 2>/dev/null)" "absent" \
      "there is no resolver configuration to leak a query through"
assert_eq "$(ax 'ls /sys/class/net' 2>/dev/null | tr -d '\n ')" "lo" \
      "and /sys/class/net agrees: lo, and nothing else"
assert_eq "$(ax 'env | grep -c HTTPS_PROXY || true' 2>/dev/null | tr -d ' ')" "0" \
      "no proxy is advertised to a sandbox with no egress"
rc="$(ax 'curl -s -o /dev/null --max-time 5 https://example.com >/dev/null 2>&1; echo $?' 2>/dev/null | tr -d ' ')"
check "$([ -n "$rc" ] && [ "$rc" != "0" ] && echo yes || echo no)" \
      "the offline guest cannot reach the internet either (curl exit ${rc:-none})"
adown

say "online battery — allowlist, ports, parser shapes, resolved-address check"
if ! slab_net_ok; then
  skip "online battery: the VM host cannot reach example.com right now (network gate; see the suite header)"
  slab_done
  exit 0
fi

# Two sandboxes for the whole online battery. B first, allowed nip.io so the
# resolved-address check has a name that may resolve; its proxy address is
# also what the foreign-peer probes aim at. Then A, allowed example.com, which
# runs everything else. The harness's boot state is single-slot, so B's pid
# and id are held here and B is stopped through them at the end — the EXIT
# trap would catch it anyway, but a suite that stops what it opened says more
# than one that relies on the trap.
aup -allow nip.io
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
B_ID="$AUP_ID"; B_PID="$AUP_PID"
b_proxy="$(ax 'env | grep HTTPS_PROXY' 2>/dev/null | sed 's/^HTTPS_PROXY=//' | tr -d '\r')"
assert_eq "$(grep -cE '^http://169\.254\.[0-9.]+:[0-9]+$' <<<"$b_proxy")" "1" \
      "the proxy topology is 169.254/30 with a kernel-assigned port"

# The post-resolution address check, on B: nip.io maps <ip>.nip.io to <ip>,
# so these names resolve to the addresses a hijacked answer would point at.
# The refusal is the proxy's, AFTER resolution, and the record holds the
# resolved address even though the 403 the guest reads names none.
cat > "$SLAB_WORK/addrcheck.py" <<'PY'
import os, socket

host, port = os.environ["HTTPS_PROXY"].split("//")[-1].rsplit(":", 1)

def connect_probe(name):
    s = socket.create_connection((host, int(port)), timeout=15)
    s.settimeout(15)
    s.sendall(f"CONNECT {name}:443 HTTP/1.1\r\nHost: {name}:443\r\n\r\n".encode())
    buf = b""
    try:
        while len(buf) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
    except socket.timeout:
        pass
    s.close()
    return buf.decode("latin1", "replace")

for name in ("169-254-169-254.nip.io", "10-0-0-1.nip.io"):
    r = connect_probe(name)
    print(name, r.split("\r\n", 1)[0], "[egress.resolved_addr]" in r)
PY
addr="$(ax_script python3 "$SLAB_WORK/addrcheck.py" 2>/dev/null)"
echo "$addr" | sed 's/^/  | /'
assert_contains "$addr" "169-254-169-254.nip.io HTTP/1.1 403 Forbidden True" \
      "the metadata address is refused after resolution, naming the denial ID"
assert_contains "$addr" "10-0-0-1.nip.io HTTP/1.1 403 Forbidden True" \
      "an RFC1918 address is refused the same way"
assert_grep_event 'unsafe_resolved_address' "the record holds the resolved-address refusals" "$B_ID"
assert_grep_event '"resolved_addr"' "and records the address the name actually resolved to" "$B_ID"

aup -allow example.com
if [ -z "$AUP_ID" ]; then
  AUP_PID="$B_PID"; AUP_ID="$B_ID"; adown
  slab_done; exit 1
fi

code() { ax "curl -s -o /dev/null -w '%{http_code}' --max-time 15 '$1'" 2>/dev/null; }

assert_eq "$(code https://example.com)" "200" "an allowlisted origin answers"
assert_eq "$(code https://www.example.com)" "200" "its subdomain answers too (dot-anchored, not suffix)"
assert_eq "$(code https://EXAMPLE.COM)" "200" "the allowlist is case-insensitive"
assert_eq "$(code https://example.com.)" "200" "a trailing dot normalises to the same host"

# The refusals, over raw sockets for the reason above.
cat > "$SLAB_WORK/refusals.py" <<'PY'
import os, socket

host, port = os.environ["HTTPS_PROXY"].split("//")[-1].rsplit(":", 1)

def connect_probe(authority):
    s = socket.create_connection((host, int(port)), timeout=15)
    s.settimeout(15)
    s.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    buf = b""
    try:
        while len(buf) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
    except socket.timeout:
        pass
    s.close()
    return buf.decode("latin1", "replace")

for authority in ("notexample.com:443", "example.com:22", "example.com:8080", "example.com:8443"):
    r = connect_probe(authority)
    print(authority, r.split("\r\n", 1)[0], "[egress.host]" in r, "[egress.port]" in r)
PY
refusals="$(ax_script python3 "$SLAB_WORK/refusals.py" 2>/dev/null)"
echo "$refusals" | sed 's/^/  | /'
assert_contains "$refusals" "notexample.com:443 HTTP/1.1 403 Forbidden True False" \
      "the suffix trap is refused as a HOST miss, not a port miss"
assert_contains "$refusals" "example.com:22 HTTP/1.1 403 Forbidden False True" \
      "port 22 on an allowlisted host is refused as a PORT miss"
assert_contains "$refusals" "example.com:8080 HTTP/1.1 403 Forbidden False True" "port 8080 is refused"
assert_contains "$refusals" "example.com:8443 HTTP/1.1 403 Forbidden False True" "port 8443 is refused"
assert_grep_event 'not_in_allowlist' "the record holds the allowlist refusals"
assert_grep_event 'port_not_allowed' "the record holds the port refusals"

# The parser shapes, driven with raw sockets so no client library can be the
# thing being tested. Pinned live against the proxy (and where the audit's
# summary was looser than the machine, the machine wins, per §6's own rule):
# the CONNECT TARGET decides a tunnel — a lying Host header cannot steer it —
# origin-form's 400 and 403 are the refusal shapes the audit described, and
# the plain absolute-URI path rebuilds the request with Host from the URI,
# which is why no-Host and evil-Host both answer 200 there: IA-I5's rewrite,
# correct and now pinned here rather than merely observed once.
cat > "$SLAB_WORK/proxyshapes.py" <<'PY'
import os, socket

host, port = os.environ["HTTPS_PROXY"].split("//")[-1].rsplit(":", 1)
target = "example.com"

def talk(raw, timeout=15):
    s = socket.create_connection((host, int(port)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(raw)
    buf = b""
    try:
        while len(buf) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\r\n\r\n" in buf:
                break
    except socket.timeout:
        pass
    s.close()
    return buf.decode("latin1", "replace")

status = lambda r: r.split("\r\n", 1)[0] if r else "(no answer)"

print("CONNECT-OK-TARGET", status(talk(f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode())))
print("CONNECT-EVIL-TARGET", status(talk(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")))
print("ORIGIN-NO-HOST", status(talk(b"GET / HTTP/1.1\r\n\r\n")))
print("ORIGIN-EVIL-HOST", status(talk(b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n")))
print("ABS-PLAIN", status(talk(f"GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())))
print("ABS-TLS", status(talk(f"GET https://{target}/ HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n".encode())))
print("ABS-REBUILD-NO-HOST", status(talk(f"GET http://{target}/ HTTP/1.1\r\n\r\n".encode())))
print("ABS-REWRITE-EVIL-HOST", status(talk(f"GET http://{target}/ HTTP/1.1\r\nHost: evil.com\r\nConnection: close\r\n\r\n".encode())))
PY
shapes="$(ax_script python3 "$SLAB_WORK/proxyshapes.py" 2>/dev/null)"
echo "$shapes" | sed 's/^/  | /'
assert_contains "$shapes" "CONNECT-OK-TARGET HTTP/1.1 200" "CONNECT tunnels to the allowlisted origin"
assert_contains "$shapes" "CONNECT-EVIL-TARGET HTTP/1.1 403" "and a lying Host header cannot steer a CONNECT to an allowed origin — the target decides"
assert_contains "$shapes" "ORIGIN-NO-HOST HTTP/1.1 400" "origin-form with no Host header is refused, not guessed"
assert_contains "$shapes" "ORIGIN-EVIL-HOST HTTP/1.1 403" "origin-form to a refused host is refused"
assert_contains "$shapes" "ABS-PLAIN HTTP/1.1 200" "an absolute-URI plain request is served by the same policy"
assert_contains "$shapes" "ABS-TLS HTTP/1.1 200" "an absolute-URI https request is served by the same policy"
assert_contains "$shapes" "ABS-REBUILD-NO-HOST HTTP/1.1 200" "plain absolute-URI without Host is rebuilt with the URI's host (IA-I5) — safe by construction"
assert_contains "$shapes" "ABS-REWRITE-EVIL-HOST HTTP/1.1 200" "and a plain absolute-URI's lying Host is rewritten to the origin (IA-I5)"

# A foreign peer. B's proxy address, read out of B's own env, probed from this
# guest: the nft F9 rule drops it silently — no RST, no ICMP, nothing to time
# down and nothing to leak.
cat > "$SLAB_WORK/peerprobe.py" <<PY
import socket
host, port = "$b_proxy".rsplit("//", 1)[-1].rsplit(":", 1)
s = socket.socket()
s.settimeout(5)
try:
    s.connect((host, int(port)))
    s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    try:
        data = s.recv(1024)
        print("ANSWERED", repr(data[:40]))
    except socket.timeout:
        print("SILENT")
except Exception as e:
    print("SILENT", type(e).__name__)
s.close()
PY
probe="$(ax_script python3 "$SLAB_WORK/peerprobe.py" 2>/dev/null)"
assert_contains "$probe" "SILENT" "another sandbox's proxy drops a guest's probe silently"

# The VM side of the same wall: a process on the VM itself, dialling B's proxy
# address, is a foreign peer too — the iifname rule drops it with no bytes and
# no error text.
vm_probe="$(python3 - "${b_proxy#http://}" <<'PY'
import socket, sys
host, port = sys.argv[1].rsplit(":", 1)
s = socket.socket(); s.settimeout(5)
try:
    s.connect((host, int(port))); s.sendall(b"GET / HTTP/1.1\r\n\r\n")
    try:
        s.recv(1024); print("ANSWERED")
    except socket.timeout: print("SILENT")
except Exception as e: print("SILENT", type(e).__name__)
s.close()
PY
)"
assert_contains "$vm_probe" "SILENT" "a VM-side process probing the proxy is dropped silently too"

adown
AUP_PID="$B_PID"; AUP_ID="$B_ID"; AUP_TRAILING=1
adown

slab_done
