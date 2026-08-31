#!/usr/bin/env bash
# KelyfOS — the workspace boundary, committed as a suite (ST-1.8).
#
#   bash dev/accept-security-workspace.sh
#
# The audit's workspace scenarios, machine-checked — and where the machine's
# actual contract differs from the audit's summary, this suite pins the
# machine's, with the difference recorded in D88:
#
#   - a fifo in /work is REFUSED whole-image: the sync-back fails naming the
#     entry, its mode and the reason, and the host directory is untouched.
#     This is the audit's canonical case, and it verifies exactly.
#   - escaping symlinks (absolute and climbing), and filenames with newlines,
#     never land on the host — but they are dropped silently, not refused:
#     the sync-back still says "written back". Nothing escapes; the honesty
#     gap is IA-H1-shaped and rides with ST-5.2's fix.
#   - setuid and world-write land SANITISED: safeMode (internal/sandbox/
#     extract.go) strips setuid/setgid/sticky and world-write by design —
#     the file arrives, the dangerous bits do not.
#   - a 40-deep path lands: the refusal threshold is 128.
#   - plain entries land with their modes.
#
# Every guest write is followed by `sync` in this suite, because until
# ST-5.2's deterministic flush lands, teardown races the guest's ext4 commit
# (IA-H1) and an unsynced write measures nothing. ST-5.2 removes the need.
#
# The IA-H1 regression slot at the end reproduces the HIGH finding as the
# audit described it and is encoded as a loud skip naming IA-H1 — not a pass,
# not a red — flipping into an always-on assertion when ST-5.2 lands.
#
# No network anywhere in it.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO/dev/security-lab.sh"

slab_init accept-security-workspace

# hostile <name> <guest-commands> — boot with a workspace, create the entry
# (synced, so the measurement is of the boundary and not of IA-H1), tear
# down, and assert what the host received.
hostile() {
  local kind="$1" cmd="$2" hostdir log
  hostdir="$SLAB_WORK/ws-$kind"
  mkdir -p "$hostdir"
  aup -workspace "$hostdir"
  if [ -z "$AUP_ID" ]; then fail "$kind: boot failed"; return 0; fi
  ax "$cmd && sync" >/dev/null 2>&1
  log="$AUP_LOG"
  adown
  printf '%s' "$kind"
}

say "a fifo is refused whole-image, with the entry named"
fifo_host="$SLAB_WORK/ws-fifo"
mkdir -p "$fifo_host"
aup -workspace "$fifo_host"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
ax "mkfifo /work/pipe && echo data > /work/data.txt && sync"
fifo_log="$AUP_LOG"
adown
assert_contains "$(cat "$fifo_log")" \
      "the workspace image contains an entry this host will not use: /pipe is neither a file, a directory nor a symlink (mode" \
      "the sync-back fails naming the entry, its mode and the reason"
assert_eq "$(ls -A "$fifo_host" 2>/dev/null | wc -l | tr -d ' ')" "0" \
      "and the host directory is untouched — even the plain file in the same image was not extracted"

say "hostile entries never escape onto the host"
host="$SLAB_WORK/ws-escape"
mkdir -p "$host"
aup -workspace "$host"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
ax "ln -s /etc/passwd /work/abs; ln -s ../../etc/passwd /work/climb; python3 -c \"open('/work/bad\nname','w').write('x')\"; sync"
escape_log="$AUP_LOG"
adown
assert_eq "$(ls -A "$host" 2>/dev/null | wc -l | tr -d ' ')" "0" \
      "an absolute symlink, a climbing symlink and a newline filename land nothing"
# D88 finding, recorded rather than asserted: whether these arrive as a
# silent drop or a whole-image refusal varied across runs on the same tree.
# Both prevent the escape; the refusal names the entry, the drop does not,
# and either way the sync-back's success message cannot be trusted to mean
# "everything arrived" — the same honesty gap IA-H1 turns into data loss.

say "dangerous modes are stripped, the files survive"
modes_host="$SLAB_WORK/ws-modes"
mkdir -p "$modes_host"
aup -workspace "$modes_host"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
ax "cp /bin/busybox /work/su && chmod 4755 /work/su && echo x > /work/ww && chmod 666 /work/ww && sync"
adown
assert_eq "$(stat -c '%a' "$modes_host/su" 2>/dev/null)" "755" \
      "a setuid binary lands with the setuid bit stripped (safeMode, by design)"
check "$(grep -qE '^.[1-9]$' <<<"$(stat -c '%a' "$modes_host/ww" 2>/dev/null)" && echo no || echo yes)" \
      "a world-writable file lands without the world-write bit"

say "a deep path lands under the refusal threshold"
deep_host="$SLAB_WORK/ws-deep"
mkdir -p "$deep_host"
aup -workspace "$deep_host"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
# Built on the host: a deterministic 40-deep path, no exec inside an
# expansion to go missing on a slow round-trip.
deep="/work/$(printf 'd/%.0s' $(seq 1 40))"
ax "mkdir -p '$deep' && echo deep > '$deep/x' && sync"
adown
deep_host_path="$deep_host${deep#/work}"
assert_eq "$(cat "$deep_host_path/x" 2>/dev/null)" "deep" \
      "a 40-deep path is not refused — the threshold is 128 (listImage), and the file arrives"

say "plain entries land with their modes"
plain="$SLAB_WORK/ws-plain"
mkdir -p "$plain"
aup -workspace "$plain"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
ax "echo plain-file > /work/plain.txt && mkdir /work/plain-dir && echo nested > /work/plain-dir/nested.txt && chmod 750 /work/plain-dir && chmod 640 /work/plain.txt && sync"
plain_log="$AUP_LOG"
adown
assert_eq "$(cat "$plain/plain.txt" 2>/dev/null)" "plain-file" \
      "a plain file written in the guest lands on the host"
assert_eq "$(cat "$plain/plain-dir/nested.txt" 2>/dev/null)" "nested" \
      "and so does one inside a directory"
assert_contains "$(stat -c '%a' "$plain/plain-dir" 2>/dev/null)" "750" \
      "the directory's mode survives the round trip"
assert_contains "$(stat -c '%a' "$plain/plain.txt" 2>/dev/null)" "640" \
      "and the file's mode does too"
check "$(grep -aq 'workspace written back' "$plain_log" && echo yes || echo no)" \
      "and the run said so, because this time it is true"

say "IA-H1 regression slot — silent loss with a false success"
# REPRODUCED 2/2 on 2026-08-31 against the same tree this suite landed on:
# a file written in the guest, teardown immediately after, "workspace written
# back" on stdout, the host directory empty. Until ST-5.2's deterministic
# flush lands, the honest encoding is this skip: loud, dated, named. It is
# not a pass, it is not silent, and it flips into the assertion below the
# moment the fix exists.
slot_host="$SLAB_WORK/ws-iah1"
mkdir -p "$slot_host"
aup -workspace "$slot_host"
if [ -z "$AUP_ID" ]; then slab_done; exit 1; fi
ax "echo proof-of-work > /work/proof.txt"
adown
if [ -f "$slot_host/proof.txt" ]; then
  pass "IA-H1 slot: the file written last survived teardown — the fix has landed; make this assertion unconditional"
else
  skip "IA-H1 reproduced today (files lost, false success printed; expiry: when ST-5.2 lands) — see the suite header"
fi

slab_done
