#!/usr/bin/env bash
# KelyfOS — every refusal names its fix (E5-4).
#
#   bash dev/accept-denials.sh
#
# The catalog's own invariants are unit-tested, and `make docs` fails the build
# when an entry is raised nowhere. Neither of those proves the part that
# matters: that a person — or an agent — who hits a wall in a real run is handed
# something they can act on. So this drives real refusals out of a real binary
# and a real guest, and checks what came back.
#
# Two of them are checked from inside the sandbox on purpose. An egress denial
# is read by whatever made the request, which is usually not a human at a
# terminal, and a fix line that only ever reaches the host is a fix line the
# thing that got refused never sees.
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

# A refusal is three parts: what was refused, the ID in brackets, and a fix line
# indented beneath. Every one of them is held to all three.
shaped() {
  local text="$1" id="$2" want="$3" name="$4"
  local ok=yes
  grep -q "\[$id\]" <<<"$text" || ok=no
  grep -q "^    " <<<"$text" || ok=no
  grep -qF "$want" <<<"$text" || ok=no
  check "$ok" "$name"
  if [ "$ok" = "no" ]; then sed 's/^/      | /' <<<"$text"; fi
}

WORK="$(mktemp -d)"
cleanup() {
  pkill -f "$BIN/kelyfos run" 2>/dev/null
  sleep 1
  for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

say "KelyfOS — every refusal names its fix"
echo "  kelyfos  $(kelyfos version 2>/dev/null || echo 'not on PATH')"
flavor="$(python3 -c "import json,os;print(json.load(open(os.path.expanduser('~/.cache/kelyfos/out/$(uname -m)/image.json')))['flavor'])" 2>/dev/null || echo dev)"

cat > kelyfos.toml <<TOML
[sandbox]
image = "$flavor"

[resources]
cpus = 2
mem  = "1G"
TOML

say "a flag above a ceiling"
out="$(kelyfos run --cpus 8 -- true 2>&1)"
sed 's/^/  | /' <<<"$out"
shaped "$out" "ceiling.flag" "lower the flag" "the ceiling refusal names the file and the fix"
check "$(grep -q 'kelyfos.toml:5' <<<"$out" && echo yes || echo no)" \
      "and the line in the file the ceiling came from"

say "a credential bound to a domain the sandbox cannot reach"
export TOKEN=not-a-real-token
out="$(kelyfos run --allow example.com --secret TOKEN@api.stripe.com -- true 2>&1)"
sed 's/^/  | /' <<<"$out"
shaped "$out" "secret.unbound" "add api.stripe.com to --allow" \
       "the unbound-secret refusal names the domain to add"

say "a domain that is not in the allowlist, as the guest sees it"
(timeout 300 kelyfos run --allow example.com > run.log 2>&1 &)
for i in $(seq 1 60); do grep -q "Ctrl-C" run.log 2>/dev/null && break; sleep 1; done
if ! grep -q "Ctrl-C" run.log; then
  fail "the sandbox never came up; the guest-side checks cannot run"
  tail -5 run.log
else
  # Plain HTTP: the refusal is the response, so the guest reads the whole of it.
  kelyfos exec 'curl -s http://api.stripe.com/v1/charges' > guest.txt 2>&1
  sed 's/^/  | /' guest.txt
  out="$(cat guest.txt)"
  shaped "$out" "egress.host" 'add allow = ["api.stripe.com"] to kelyfos.toml' \
         "the guest is told the domain and the edit that would allow it"
  check "$(grep -q -- '--allow api.stripe.com' guest.txt && echo yes || echo no)" \
        "and the flag that would allow it for one run"

  # HTTPS: the refusal answers a CONNECT, and curl throws the body away before
  # anybody reads it. The host is where that fix line has to land, so it does.
  kelyfos exec 'curl -s https://api.stripe.com/v1/charges; curl -s https://api.stripe.com/v1/x' \
      > tunnel.txt 2>&1
  sed 's/^/  | /' tunnel.txt
  check "$(grep -q 'api.stripe.com' tunnel.txt && echo no || echo yes)" \
        "a refused CONNECT tells curl almost nothing, which is why the next check exists"
  hostside="$(grep -A1 'egress.host' run.log)"
  shaped "$hostside" "egress.host" 'add allow = ["api.stripe.com"] to kelyfos.toml' \
         "the host running the sandbox is told, with the fix"
  check "$([ "$(grep -c 'egress.host' run.log)" = "1" ] && echo yes || echo no)" \
        "and told once, however many times the guest retried"

  kelyfos exec 'curl -s http://example.com:8080/' > guest2.txt 2>&1
  sed 's/^/  | /' guest2.txt
  shaped "$(cat guest2.txt)" "egress.port" "use 80 or 443" \
         "a permitted domain on an unpermitted port says which ports there are"

  session="$(kelyfos log --list | sed -n 1p | awk '{print $1}')"
  kelyfos log --session "$session" > log.txt 2>/dev/null
  check "$(grep -q 'api.stripe.com' log.txt && echo yes || echo no)" \
        "and the refusal is in the record, not only on the guest's terminal"
  pkill -f "$BIN/kelyfos run" 2>/dev/null; sleep 2
fi

say "every ID a refusal printed is a heading in the generated reference"
ids="$(cat <<'EOF'
ceiling.flag
secret.unbound
egress.host
egress.port
EOF
)"
missing=0
for id in $ids; do
  grep -q "^## \`$id\`$" "$REPO/docs/reference/denials.md" || { missing=$((missing+1)); echo "  missing: $id"; }
done
check "$([ "$missing" = "0" ] && echo yes || echo no)" \
      "each ID looks up in docs/reference/denials.md"

say "and every entry in the catalog carries a fix line there"
total="$(grep -c '^## `' "$REPO/docs/reference/denials.md")"
withfix="$(grep -c '^    ' "$REPO/docs/reference/denials.md")"
echo "  $total entries, $withfix fix lines"
check "$([ "$total" -gt 0 ] && [ "$withfix" -ge "$total" ] && echo yes || echo no)" \
      "no entry in the reference is a dead end"

say "summary"
printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
printf '\n  %d passed, %d failed\n' "$PASSES" "$FAILURES"
[ "$FAILURES" -eq 0 ]
