#!/usr/bin/env bash
# KelyfOS — the E2B-compatible shim, over real HTTP (P6-18, §1 criterion 5).
#
#   bash dev/accept-shim.sh
#
# The fourteenth acceptance suite, and the one that discharges the criterion
# nobody owned: "an E2B-compatible API shim passes an SDK smoke test". D51
# re-worded that criterion and this is what backs the re-wording.
#
# **Why this drives HTTP rather than the SDK.** The E2B Python SDK shipped
# 2.41.0 through 2.45.1 in three days (19–21 August 2026). A suite pinned to one
# version proves compatibility with a version superseded within the week; a suite
# tracking the latest hands a third party the ability to turn this project's main
# red. `docs/compatibility.md` §3 already places the shim outside the
# compatibility promise for that exact reason.
#
# So this tests the half this project owns and can keep true: the REST subset the
# shim actually serves, driven over a real socket with curl, booting real
# microVMs. What it deliberately does not claim is that any particular SDK
# release works — `docs/e2b-shim.md` carries the SDK path and the variables the
# current SDK reads, re-verified per release rather than pinned.
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

ADDR="127.0.0.1:3123"
BASE="http://$ADDR"
WORK="$(mktemp -d)"
SHIM_PID=""
MINT_PID=""
cleanup() {
  [ -n "$SHIM_PID" ] && kill "$SHIM_PID" 2>/dev/null
  [ -n "$MINT_PID" ] && kill "$MINT_PID" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — the E2B-compatible shim over HTTP"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"
printf '[sandbox]\nimage = "%s"\n\n[resources]\ncpus = 1\nmem = "512M"\n' "$flavor" > kelyfos.toml

# --- the shim comes up -------------------------------------------------------

say "1. the shim serves, says so, and requires a credential"
# P7-17/F2: a token is minted per process unless --insecure-no-token is typed.
# The suite supplies its own so every request below can carry it, and the next
# section proves the minting default separately.
export KELYFOS_SHIM_TOKEN="accept-shim-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d " \n")"
AUTH=(-H "Authorization: Bearer $KELYFOS_SHIM_TOKEN")
kelyfos shim --addr "$ADDR" --image "$flavor" > shim.log 2>&1 &
SHIM_PID=$!
for _ in $(seq 1 60); do
  curl -fsS "${AUTH[@]}" -o /dev/null "$BASE/health" 2>/dev/null && break
  sleep 0.5
done

code="$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' "$BASE/health")"
check "$([ "$code" = 204 ] && echo yes || echo no)" "GET /health answers 204 with the token (got $code)"

code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE/health")"
check "$([ "$code" = 401 ] && echo yes || echo no)" "…and 401 without it (got $code)"
code="$(curl -s -H 'Authorization: Bearer wrong' -o /dev/null -w '%{http_code}' "$BASE/health")"
check "$([ "$code" = 401 ] && echo yes || echo no)" "…and 401 to the wrong token (got $code)"

# The token this shim did NOT have to be told about: a second shim, on another
# port, with the variable unset, mints one and prints it.
env -u KELYFOS_SHIM_TOKEN kelyfos shim --addr 127.0.0.1:3125 > minted.log 2>&1 &
MINT_PID=$!
sleep 2
kill "$MINT_PID" 2>/dev/null; wait "$MINT_PID" 2>/dev/null
MINT_PID=""
minted="$(cat minted.log)"
check "$(printf '%s' "$minted" | grep -Eq 'token: [0-9a-f]{64}' && echo yes || echo no)" \
  "a shim started with no KELYFOS_SHIM_TOKEN mints one and prints it"
check "$(printf '%s' "$minted" | grep -q 'export KELYFOS_SHIM_TOKEN=' && echo yes || echo no)" \
  "…with the export line that carries it to a client"

# It answers before any sandbox exists, which is what makes it a liveness probe
# for the shim rather than for a machine.
check "$(grep -q 'listening on' shim.log && echo yes || echo no)" "the shim names the address it listened on"

# --- the control plane -------------------------------------------------------

say "2. POST /sandboxes boots a real microVM"
created="$(curl -sS "${AUTH[@]}" -X POST "$BASE/sandboxes" -H 'content-type: application/json' -d '{}')"
echo "  $created"
sbx="$(printf '%s' "$created" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sandboxID",""))' 2>/dev/null)"
check "$([ -n "$sbx" ] && echo yes || echo no)" "the response carries a sandboxID ($sbx)"
check "$(pgrep -f firecracker >/dev/null && echo yes || echo no)" "a firecracker process is running"

# The E2B response shape, which is the whole point of the door being compatible.
for field in templateID sandboxID clientID envdVersion; do
  check "$(printf '%s' "$created" | grep -q "\"$field\"" && echo yes || echo no)" "the response carries $field"
done

say "3. a templateID is echoed and not honoured"
# Stated in docs/e2b-shim.md and worth a test rather than a sentence: the shim
# has one image, set by the operator, and no request parameter widens it.
echoed="$(curl -sS "${AUTH[@]}" -X POST "$BASE/sandboxes" -H 'content-type: application/json' \
  -d '{"templateID":"definitely-not-a-real-template"}')"
sbx2="$(printf '%s' "$echoed" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sandboxID",""))' 2>/dev/null)"
check "$(printf '%s' "$echoed" | grep -q 'definitely-not-a-real-template' && echo yes || echo no)" \
  "the templateID a client asked for is echoed back"
check "$([ -n "$sbx2" ] && echo yes || echo no)" "…and a sandbox booted anyway, on the operator's image"

say "4. GET /sandboxes lists what is running"
listed="$(curl -sS "${AUTH[@]}" "$BASE/sandboxes")"
n="$(printf '%s' "$listed" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"
check "$([ "$n" -ge 2 ] && echo yes || echo no)" "both sandboxes are listed (saw $n)"

# --- files, which is what an SDK smoke test actually exercises ----------------

say "5. files go in and come back out, binary-safe"
# One sandbox at a time for the file routes: the SDK addresses envd by URL per
# sandbox and this shim does not, so it refuses to guess which one is meant.
curl -sS "${AUTH[@]}" -X DELETE "$BASE/sandboxes/$sbx2" -o /dev/null -w '' || true
sleep 2

printf 'hello from an acceptance test\n' > payload.txt
w="$(curl -sS "${AUTH[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/files?path=/work/hello.txt" \
      --data-binary @payload.txt)"
check "$([ "$w" = 200 ] || [ "$w" = 201 ] || [ "$w" = 204 ] && echo yes || echo no)" \
  "POST /files writes (got $w)"

got="$(curl -sS "${AUTH[@]}" "$BASE/files?path=/work/hello.txt")"
check "$([ "$got" = "$(cat payload.txt)" ] && echo yes || echo no)" "GET /files reads back exactly what was written"

# Binary, because "binary-safe" is a claim docs/e2b-shim.md makes.
head -c 4096 /dev/urandom > blob.bin
curl -sS "${AUTH[@]}" -o /dev/null -X POST "$BASE/files?path=/work/blob.bin" --data-binary @blob.bin
curl -sS "${AUTH[@]}" "$BASE/files?path=/work/blob.bin" > blob.out
check "$(cmp -s blob.bin blob.out && echo yes || echo no)" "4 KiB of random bytes survive the round trip unchanged"

say "6. a web page cannot reach it, and a bind off loopback needs a credential"
# P7-17/F2. The shim serves on a loopback port with no authentication, which is
# the exact configuration a page the developer visits can reach: POST /files is
# a CORS-"simple" multipart request and POST /sandboxes needed no parseable body
# at all. Driven here over the real socket, because header handling in an
# httptest recorder is not the same thing as header handling in net/http's own
# server.
for hdr in 'Origin: http://evil.example' 'Sec-Fetch-Site: cross-site'; do
  c="$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/sandboxes" -H "$hdr" -d '{}')"
  check "$([ "$c" = 403 ] && echo yes || echo no)" "a request carrying '$hdr' is refused (got $c)"
done
c="$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/files?path=/work/pwned" \
      -H 'Origin: http://evil.example' -F 'file=@payload.txt')"
check "$([ "$c" = 403 ] && echo yes || echo no)" "a cross-origin form POST to /files is refused (got $c)"

# DNS rebinding: the one shape Origin and Sec-Fetch-Site cannot see, because a
# rebound page is same-origin with itself. The Host header is what it cannot
# change.
c="$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' -H 'Host: evil.example:3123' "$BASE/health")"
check "$([ "$c" = 403 ] && echo yes || echo no)" "a Host header naming a rebindable name is refused (got $c)"
c="$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' -H "Host: localhost:${ADDR##*:}" "$BASE/health")"
check "$([ "$c" = 204 ] && echo yes || echo no)" "…and localhost still works, which is what people type (got $c)"

# The decode error createSandbox used to discard: a body that is not JSON cost
# the host a microVM.
c="$(curl -s "${AUTH[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/sandboxes" -d 'not json at all')"
check "$([ "$c" = 400 ] && echo yes || echo no)" "a body that is not JSON answers 400 rather than booting (got $c)"

# And the bind itself. A shim off loopback with no credential is reachable from
# the LAN; it now refuses to start rather than saying so in a document.
off="$(env -u KELYFOS_SHIM_TOKEN kelyfos shim --addr 0.0.0.0:3124 --insecure-no-token 2>&1; echo "rc=$?")"
check "$(printf '%s' "$off" | grep -q 'rc=0' && echo no || echo yes)" "kelyfos shim refuses a non-loopback bind with no token"
check "$(printf '%s' "$off" | grep -q 'KELYFOS_SHIM_TOKEN' && echo yes || echo no)" "…and the refusal names the fix"

say "7. a route the shim does not implement says so"
ni="$(curl -s "${AUTH[@]}" -o body.txt -w '%{http_code}' "$BASE/sandboxes/$sbx/commands")"
check "$([ "$ni" != 200 ] && echo yes || echo no)" "an unimplemented route does not answer 200 (got $ni)"
check "$(grep -qi 'not implemented\|mcp' body.txt && echo yes || echo no)" \
  "…and the body says what to use instead: $(sed -n '1,1p' body.txt | cut -c1-70)"

# --- the record, which is the thing E2B does not give you --------------------

say "8. every shim sandbox gets its own flight recorder"
# ~/.cache/kelyfos/sessions/<sandboxID>/events.jsonl, and the sandbox id is the
# one the shim handed back — so this checks the record of a named machine rather
# than whichever file happens to be newest.
rec="${KELYFOS_CACHE:-$HOME/.cache/kelyfos}/sessions/$sbx/events.jsonl"
check "$([ -f "$rec" ] && echo yes || echo no)" "the sandbox the shim named has a record of its own"
if [ -f "$rec" ]; then
  check "$(grep -q 'created through the E2B shim' "$rec" && echo yes || echo no)" \
    "…and its session.start says the sandbox came through the shim"
  check "$(grep -q '"type":"file.write"' "$rec" && echo yes || echo no)" \
    "…and the file written over HTTP is in it"
  check "$(grep -q 'hello from an acceptance test' "$rec" && echo no || echo yes)" \
    "…by path and digest, without the content"
  check "$(kelyfos log --verify --session "$sbx" >/dev/null 2>&1 && echo yes || echo no)" \
    "…and the chain verifies"
fi

say "9. DELETE /sandboxes/{id} stops the machine"
d="$(curl -sS "${AUTH[@]}" -o /dev/null -w '%{http_code}' -X DELETE "$BASE/sandboxes/$sbx")"
check "$([ "$d" = 200 ] || [ "$d" = 204 ] && echo yes || echo no)" "DELETE answers (got $d)"
sleep 2
after="$(curl -sS "${AUTH[@]}" "$BASE/sandboxes" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo -1)"
check "$([ "$after" = 0 ] && echo yes || echo no)" "nothing is left running (saw $after)"

# --- the summary -------------------------------------------------------------

say "Summary"
for line in "${SUMMARY[@]}"; do echo "  $line"; done
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
echo
echo "  What this proves: the REST subset docs/e2b-shim.md documents, driven over a"
echo "  real socket against real microVMs. What it does not prove: that any given"
echo "  release of the E2B SDK works — that is somebody else's release cadence and"
echo "  docs/compatibility.md puts it outside the promise on purpose (D51)."
[ "$FAILURES" -eq 0 ]
