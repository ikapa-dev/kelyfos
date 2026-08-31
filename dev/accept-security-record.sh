#!/usr/bin/env bash
# KelyfOS — the tamper-evident record, committed as a suite (ST-1.4).
#
#   bash dev/accept-security-record.sh
#
# The audit's record scenarios, machine-checked: an exported report verifies
# clean; a flipped byte inside the chain is named to the event it corrupts;
# a removed chain marker is refused rather than guessed; rendered output
# escapes attacker-controlled strings (RENDER); and tail truncation with
# recomputed claims verifies — today — which is the record's own documented
# keyless limit, confirmed live by the audit (IA-M2). That last check is
# written as EXPECTED-CURRENT with a TODO(IA-M2) marker so the day signing
# lands (the P6-7 direction), the suite fails here and the flip is the
# regression test for the fix, not a manual edit nobody remembers.
#
# No network: the whole suite runs against one offline sandbox's record.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-record

aup
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi

# Give the record something worth tampering with, including the two payloads
# the RENDER checklist cares about: a script tag in command output and an
# onerror attribute in a filename the agent created. Both are quoted because
# the guest's busybox sh parses unquoted < and > as redirections (§8 trap 4),
# which would create files named alert(1) and teach the suite nothing.
ax "echo '<script>alert(1)</script> hello-from-record-suite'"
ax "touch '/work/<img src=x onerror=alert(1)>.txt'; echo done"

report="$SLAB_WORK/report.html"
"$BIN/kelyfos" log -session "$AUP_ID" -export "$report" >/dev/null 2>&1
check "$([ -s "$report" ] && echo yes || echo no)" "the report exported"

# The chain blob is base64, 76 columns, inside the marker (§8 trap 7).
extract_blob() {
  sed -n '/<pre id="kelyfos-chain">/,/<\/pre>/p' "$1" | sed '1d;$d' | tr -d '\n'
}

say "the record verifies, and detects"
v="$("$BIN/kelyfos" verify "$report" 2>&1)"
check "$(grep -qiE 'chain intact|verified' <<<"$v" && echo yes || echo no)" "an exported report verifies clean"

# Flip one byte of the blob — in the middle, so it lands inside a real event.
# Python, not sed: the blob spans 76-column lines, and a line-oriented edit
# cannot see the blob it is standing in.
python3 - "$report" "$SLAB_WORK/tampered.html" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
page = open(src).read()
m = re.search(r'<pre id="kelyfos-chain">(.*?)</pre>', page, re.S)
blob = m.group(1)
i = len(blob) // 2
i -= i % 4
c = blob[i]
page = page.replace(blob, blob[:i] + ("A" if c != "A" else "B") + blob[i+1:])
open(dst, "w").write(page)
PY
vt="$("$BIN/kelyfos" verify "$SLAB_WORK/tampered.html" 2>&1)"
check "$(grep -qi 'FAILED' <<<"$vt" && echo yes || echo no)" \
      "a flipped byte fails verification"
evline="$(grep -oiE '(event|line) [0-9]+[^,]*' <<<"$vt" | head -1)"
check "$([ -n "$evline" ] && echo yes || echo no)" \
      "and names the location it corrupts (${evline:-but verify said: $(head -c 70 <<<"$vt" | tr -d '\n')})"

# The marker removed: no chain to read, so the report is refused rather than
# verified as "empty".
grep -v 'kelyfos-chain' "$report" > "$SLAB_WORK/nomarker.html"
vn="$("$BIN/kelyfos" verify "$SLAB_WORK/nomarker.html" 2>&1)"
check "$(grep -qi 'no KelyfOS record' <<<"$vn" && echo yes || echo no)" \
      "a report with the chain marker removed is refused"

# Tail truncation with recomputed claims verifies TODAY. This is the record's
# own keyless limit, documented in the page footer and docs/events.md, live
# by the audit (IA-M2). When signing lands, this check flips: it must fail.
# TODO(IA-M2): flip this expectation to a refusal when ST-5.4 lands.
say "the known limit — truncation verifies today"
trunc="$SLAB_WORK/truncated.html"
tpython_out="$(python3 - "$report" "$trunc" <<'PY'
import base64, re, sys
src, dst = sys.argv[1], sys.argv[2]
page = open(src).read()
m = re.search(r'<pre id="kelyfos-chain">(.*?)</pre>', page, re.S)
if not m:
    print("no blob"); sys.exit(1)
blob = m.group(1)
raw = base64.b64decode("".join(blob.split()))
lines = raw.decode("utf-8", "replace").strip().split("\n")
kept = lines[:-1]
count = len(kept)
new_raw = ("\n".join(kept) + "\n").encode()
new_b64 = base64.b64encode(new_raw).decode()
wrapped = "\n".join(new_b64[i:i+76] for i in range(0, len(new_b64), 76))
page = page.replace(m.group(0), f'<pre id="kelyfos-chain">{wrapped}</pre>')
page = re.sub(r'\b\d+ events\b', f'{count} events', page)
open(dst, "w").write(page)
print(f"truncated to {count} events")
PY
)"
echo "  | $tpython_out"
vt="$("$BIN/kelyfos" verify "$trunc" 2>&1)"
if grep -qi 'chain intact\|verified' <<<"$vt"; then
  pass "truncation with recomputed claims verifies (EXPECTED-CURRENT — TODO(IA-M2))"
else
  fail "truncation verifies (EXPECTED-CURRENT — TODO(IA-M2)): $(head -c 80 <<<"$vt" | tr -d '\n')"
fi

say "rendered output escapes"
esc="$("$BIN/kelyfos" log -session "$AUP_ID" -export "$SLAB_WORK/render.html" >/dev/null 2>&1; cat "$SLAB_WORK/render.html")"
assert_eq "$(grep -c '<script>alert' <<<"$esc" || true)" "0" \
      "no raw script tag from command output survives rendering"
check "$(grep -qE '&lt;script&gt;' <<<"$esc" && echo yes || echo no)" \
      "the script tag is escaped in the page"
assert_eq "$(grep -c '<img src=x' <<<"$esc" || true)" "0" \
      "no raw img tag from a filename survives — onerror needs no escaping in a text node, a tag does"

adown

slab_done
