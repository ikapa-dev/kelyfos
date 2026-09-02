#!/usr/bin/env bash
# KelyfOS — the session the README's recording is made from (P5-5).
#
#   bash dev/demo-record.sh            # play it, so you can watch it work
#   bash dev/demo-record.sh --record   # play it under asciinema and render a GIF
#
# Committed, because an asset nobody can regenerate is an asset that goes stale
# silently. Everything below is a real command against a real machine: nothing
# here is typed into a mock, and if a beat stops working this script stops
# working with it.
#
# Four beats, in the order somebody meeting the product needs them:
#
#   1. a sandbox boots, and says what walls are around it
#   2. an egress it was not given is refused, with the line that fixes it
#   3. five agents come up as a graph
#   4. the record verifies
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"
# A narrow, predictable terminal: the GIF is read at README width, and a demo
# that wraps is a demo nobody finishes.
export COLUMNS=88

RECORD=0
[ "${1:-}" = "--record" ] && RECORD=1

WORK="$(mktemp -d)"
# This run gets its own KELYFOS_CACHE and tears down only the machines under
# it. The lines that used to be here -- a `pkill -f` on a kelyfos process name
# and `for p in $(pgrep firecracker); do kill "$p"; done` -- were host-wide
# questions answered with a kill, and on a machine running more than one
# worktree they took a peer's microVMs down with them (D79).
source "$REPO"/dev/scope.sh
scope_init demo-record

cleanup() {
  scope_teardown
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- the pacing -------------------------------------------------------------
# A prompt, the command as if typed, then the command. The pauses are what makes
# it watchable; they are also the whole of the difference between this and a
# script, so they are in one place and named.
BEAT=1.5   # after a command's output, before the next prompt
TYPE=0.03  # per character, while "typing"

prompt() {
  printf '\033[1;36m$\033[0m '
  local line="$*" i
  for ((i = 0; i < ${#line}; i++)); do
    printf '%s' "${line:i:1}"
    sleep "$TYPE"
  done
  printf '\n'
}
beat() { sleep "$BEAT"; }

play() {
  cd "$WORK"
  mkdir -p ws && echo "a file the agent can change" > ws/notes.md
  cp "$REPO/dev/demo-team.toml" ./kelyfos.toml
  # The team file doubles as the single-sandbox policy for the first two beats:
  # one file, so the demo does not quietly swap the ground under itself.
  printf '[sandbox]\nimage = "dev"\nallow = ["github.com"]\n\n' > single.toml
  cat kelyfos.toml >> single.toml

  # Warm the fork template before anything is shown. This run has a private
  # cache (D79), so without this the recorded `team up` is the first team of
  # this shape the machine has ever booted: five cold boots at once, which under
  # nested virtualisation take about five seconds each. The recording is meant
  # to show what the second team of the day looks like — the workers forked in
  # well under a second, the master cold because it has egress — which is the
  # shape the README's five-agent figure describes. Nothing here is printed.
  # The template is built in the background after the team is up, so wait for
  # the line that says it was cached before tearing the team down; a teardown
  # that arrives first cancels the build and the recording boots cold anyway.
  (timeout 180 kelyfos team up > warm.log 2>&1 &)
  for i in $(seq 1 240); do grep -q 'cached a fork template' warm.log 2>/dev/null && break; sleep 0.5; done
  kelyfos team down > /dev/null 2>&1 || true
  sleep 1

  # Not `clear`: it wants TERM, and the recorder's shell may not have one.
  printf '\033[2J\033[H'
  printf '\033[1;37m# KelyfOS — a sandbox an agent can only reach through tools\033[0m\n\n'
  beat

  # 1 + 2. The machine, and a refusal with its fix. Both in one pane, because
  # the fix line is printed by `run` itself and that is where somebody watching
  # a run would see it.
  prompt 'kelyfos run --policy single.toml -- kelyfos exec "curl -sS -m5 https://example.com"'
  timeout 120 kelyfos run --policy single.toml -- \
    kelyfos exec "curl -sS -m5 https://example.com" 2>&1
  beat; beat

  # 3. Five machines, and the edges between them.
  prompt 'kelyfos team up'
  (timeout 120 kelyfos team up > team.log 2>&1 &)
  for i in $(seq 1 60); do grep -q 'team up in' team.log 2>/dev/null && break; sleep 0.5; done
  cat team.log
  beat
  scope_kill_kelyfos team
  sleep 1

  # 4. The record, checked rather than described.
  prompt 'kelyfos log --verify'
  kelyfos log --verify 2>&1 | tail -3
  beat; beat
}

if [ "$RECORD" = "0" ]; then
  play
  exit 0
fi

# --- recording --------------------------------------------------------------
#
# The two tools, pinned, because an asset that cannot be regenerated the same way
# is an asset nobody will regenerate:
#
#   asciinema 2.4.0   Ubuntu 24.04's own package (`apt install asciinema`).
#                     Upstream is on 3.x and writes asciicast v3 by default;
#                     2.4.0 writes v2, which agg reads either way. Pinned to the
#                     distribution's copy so this needs no extra download.
#   agg 1.9.0         github.com/asciinema/agg, released 2026-05-29. Upstream
#                     publishes no checksum file, so the digest of the aarch64
#                     binary is recorded here rather than merely trusted:
#                       agg-aarch64-unknown-linux-gnu
#                       sha256 2b4be407b97e00e1c313a41d154ced8fa3d02c560c8f47a0db4950a2576444c9
#
# --cols and --rows are not optional. asciinema 2.4.0 records 80x24 when its
# input is not a terminal and says nothing about it, so a recording made from a
# script would silently be the wrong shape.
command -v asciinema >/dev/null || { echo "asciinema is not installed: apt install asciinema"; exit 1; }
command -v agg >/dev/null || { echo "agg is not installed: see the pin above"; exit 1; }

CAST="$REPO/docs/media/demo.cast"
GIF="$REPO/docs/media/demo.gif"
rm -f "$CAST"
asciinema rec --cols 88 --rows 30 --overwrite \
  --command "bash '${BASH_SOURCE[0]}'" "$CAST"
# --idle-time-limit trims dead air without touching the beats: it is set just
# above BEAT, so a deliberate pause survives and a wait for a machine does not.
#
# asciinema and agg are both GPL-3.0. They render an asset and are not linked
# into anything, the same relationship KelyfOS already has with the GCC that
# builds its kernel; neither is a dependency of the product.
agg --font-size 15 --idle-time-limit 1.6 --theme asciinema "$CAST" "$GIF"
ls -lh "$GIF"
