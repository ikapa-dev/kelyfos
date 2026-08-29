#!/usr/bin/env bash
# Run a job of .github/workflows/ci.yml here, in Docker, with the workflow
# file itself as the specification.
#
# Why this exists. The pipeline of record ran on GitHub Actions until the day
# the account it belonged to could not run Actions at all (D73). The first
# answer to that was dev/ci-local.sh — the `checks` job's commands copied into
# a script, with a digest pinning the copy to the original. A copy is evidence;
# the original is better evidence. `act` (github.com/nektos/act) executes a
# workflow file in a container the way the hosted runner would, with the same
# actions/checkout, setup-go and upload-artifact steps, so what runs here is
# the committed ci.yml and not anyone's transcription of it — including the
# steps a transcription cannot have: actions/checkout, setup-go and its
# post-step run here, where dev/ci-local.sh begins after the checkout the
# workflow performs and has never run them at all. When a hosted run exists
# for the same commit the two can be compared line by line; when none exists,
# this is what a Progress Log row cites.
#
# What is different from GitHub, stated rather than discovered. The container
# runs as root, where the hosted runner is a non-root user — a test that needs
# a permission to be refused must skip under root, and two did not until this
# script found them. On Apple silicon the container is linux/arm64, where the
# hosted runner is amd64. And `act` checks out the WORKING DIRECTORY of the
# repository it is run in, not a commit — so this script never runs it there.
# It makes a fresh local clone at the commit you name, runs `act` inside that,
# and removes it afterwards; an uncommitted edit in your checkout cannot leak
# into the evidence, and the summary names the commit it is evidence for.
#
# What it cannot run. The `build` job (Buildroot, hours) and the `boot` job
# (a real microVM under KVM) need a machine Docker on macOS is not. For those,
# `limactl shell kelyfos-dev -- dev/ci-local.sh --boot` is the stand-in, and
# the summary says so.
#
# Usage: dev/ci-act.sh [ref] [--job NAME] [--base SHA] [--keep]
#   dev/ci-act.sh                 the checks job, on HEAD, DCO over origin/main..HEAD
#   dev/ci-act.sh efe1d38         the checks job, on that commit
#   dev/ci-act.sh --base b55103f  DCO over b55103f..HEAD (what a push from there would carry)
#   dev/ci-act.sh --keep          leave the clone and log in place afterwards
#
# Needs: docker (the daemon running, or Docker Desktop installed on macOS —
# this starts it), and act (`brew install act`). Override the runner image
# with KELYFOS_ACT_IMAGE, the scratch root with KELYFOS_ACT_DIR.
#
# Exit status: 0 when the job passed; the job's own failure otherwise; 2 for
# a usage error; 3 when another run holds the lock. Those are this script's
# codes — `make ci-act` reports any of them as make's own 2 ("Error N" on
# stderr says which), so anything scripted against the code should call
# dev/ci-act.sh directly.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

ref="HEAD"
job="checks"
base=""
keep=0
while [ $# -gt 0 ]; do
  case "$1" in
    --job) job="$2"; shift 2 ;;
    --base) base="$2"; shift 2 ;;
    --keep) keep=1; shift ;;
    -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) ref="$1"; shift ;;
  esac
done

command -v act >/dev/null || { echo "act is not installed: brew install act (github.com/nektos/act)" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is not installed; act runs the workflow in a container" >&2; exit 1; }

# Docker Desktop on macOS is often installed and not running. Start it rather
# than fail on a socket that will exist in twenty seconds.
if ! docker info >/dev/null 2>&1; then
  if [ "$(uname -s)" = "Darwin" ] && open -a Docker 2>/dev/null; then
    echo "starting Docker Desktop…"
    for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
  fi
  docker info >/dev/null 2>&1 || { echo "the Docker daemon is not running" >&2; exit 1; }
fi

sha="$(git rev-parse --verify "${ref}^{commit}")" || { echo "not a commit: $ref" >&2; exit 2; }
short="$(git rev-parse --short "$sha")"

if [ -z "$base" ]; then
  if git rev-parse --quiet --verify origin/main >/dev/null 2>&1; then
    base="$(git rev-parse origin/main)"
  else
    base="$(git rev-parse "${sha}^" 2>/dev/null || echo 0000000000000000000000000000000000000000)"
  fi
fi

case "$(uname -m)" in
  arm64|aarch64) arch="linux/arm64" ;;
  *) arch="linux/amd64" ;;
esac
image="${KELYFOS_ACT_IMAGE:-catthehacker/ubuntu:act-latest}"

root="${KELYFOS_ACT_DIR:-${TMPDIR:-/tmp}/kelyfos-act}"
mkdir -p "$root"

# One run per machine at a time. act binds an artifact server on a fixed port
# by default and two runs of the same commit would share a scratch directory,
# so the second run of this script used to kill the first — silently, with an
# empty summary (P7-16 shape: host-level singleton state). The port and the
# directory are now per run (below); the lock is for memory, because two
# `go test ./...` on one Docker daemon is the OOM this script already avoids
# within a single run. A stale lock from a dead run is taken over.
lock="$root/lock"
if mkdir "$lock" 2>/dev/null; then
  echo $$ > "$lock/pid"
else
  other="$(cat "$lock/pid" 2>/dev/null || echo '?')"
  if [ "$other" != "?" ] && kill -0 "$other" 2>/dev/null; then
    echo "another dev/ci-act.sh (pid $other) is running on this machine; wait for it — two at once share one Docker daemon's memory and will OOM each other" >&2
    exit 3
  fi
  echo "note    taking over a stale lock left by pid $other"
  echo $$ > "$lock/pid"
fi

dir="$(mktemp -d "$root/$short.XXXXXX")"
cleanup() {
  if [ "$keep" -eq 0 ]; then
    rm -rf "$dir"
  fi
  rm -rf "$lock"
}
trap cleanup EXIT
# A signal must still reach the EXIT trap, or the lock outlives an interrupted
# run and the takeover path becomes the usual one (the lead's point).
trap 'exit 130' INT TERM HUP

# A clone, not a worktree. A worktree's .git is a one-line pointer to a
# directory under the main repository, which is a host path the container
# never sees — `git tag` inside it fails, and tools/changelog.py --check
# fails with it. A local clone carries a real .git, every tag, and every
# commit reachable from a ref; the fetch below covers a commit that is on no
# ref yet. Local clones hardlink objects, so this costs seconds, not space.
git clone -q --no-checkout "$repo" "$dir/src"
git -C "$dir/src" fetch -q "$repo" "$sha" 2>/dev/null || true
git -C "$dir/src" checkout -q --detach "$sha"

# The artifact server: loopback only (act's default is the machine's LAN
# address) and on a port that is free right now, so two runs never contend.
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"

dirty="$(git status --porcelain | wc -l | tr -d ' ')"
if [ "$dirty" -ne 0 ]; then
  echo "note    your checkout has $dirty uncommitted change(s); they are NOT part of this run — act runs the commit, from a clean clone"
fi

event="$dir/event.json"
printf '{"ref":"refs/heads/main","before":"%s","after":"%s","repository":{"name":"KelyfOS","full_name":"p4r4n0rm4l/KelyfOS","default_branch":"main"}}\n' \
  "$base" "$sha" > "$event"
artifacts="$dir/artifacts"
mkdir -p "$artifacts"
log="$dir/act-$job.log"

# How many packages `go test ./...` may run at once is decided by memory, not
# cores. GitHub's ubuntu-latest has 4 cores and 16 GiB, so the hosted job runs
# four test binaries at a time and fits. Docker Desktop hands the container
# every host core but only the VM's memory — 18 cores on 7.7 GiB here — and two
# of this repository's test binaries legitimately peak near 5 GiB each
# (internal/report's TestTwoHundredMegabyteSessionRendersSafely at ~4.8 GiB,
# internal/recorder's counterpart at ~4.2 GiB; measured with /usr/bin/time).
# Any two of those together, or eighteen ordinary ones, is an OOM kill that
# reads as "signal: killed" with no test named. So: one package at a time
# under 10 GiB, two under 20, the runner's four above that. GOFLAGS reaches
# every go invocation the job makes, including make fuzz.
mem_gib="$(docker info --format '{{.MemTotal}}' 2>/dev/null | awk '{printf "%d", $1/1073741824}')"
case "${mem_gib:-0}" in
  ''|[0-9]) p=1 ;;
  1[0-9]) p=2 ;;
  *) p=4 ;;
esac
goflags="${KELYFOS_ACT_GOFLAGS:--p=$p}"

echo "dev/ci-act.sh — ci.yml job '$job' under act"
echo "commit  $sha"
echo "base    $base (DCO range base..commit)"
echo "image   $image ($arch; GitHub's ubuntu-latest is linux/amd64 and runs as a non-root user)"
echo "goflags $goflags (package parallelism from the daemon's ${mem_gib:-?} GiB; two test binaries peak near 5 GiB each)"
echo

rc=0
(
  cd "$dir/src"
  act push -W .github/workflows/ci.yml -j "$job" \
    --eventpath "$event" \
    -P "ubuntu-latest=$image" \
    --container-architecture "$arch" \
    --artifact-server-path "$artifacts" \
    --artifact-server-addr 127.0.0.1 --artifact-server-port "$port" \
    --env "GOFLAGS=$goflags"
) > "$log" 2>&1 || rc=$?

# The step verdicts, in order, as the workflow named them.
echo "---- summary: ci.yml job '$job', act, commit $short ----"
if ! grep -qE "^\[ci/$job\] +(✅|❌)" "$log"; then
  echo "  act ran no step at all. Its own words:"
  grep -E 'level=(fatal|error)|Error:' "$log" | sed -E 's/^.*msg=//' | head -5 | sed 's/^/    /' | cut -c1-200
  [ -s "$log" ] || echo "    (empty log)"
fi
grep -E "^\[ci/$job\] +(✅|❌)" "$log" \
  | sed -E "s/^\[ci\/$job\] +//; s/  Success - /  pass  /; s/  Failure - /  FAIL  /; s/^Main //; s/ Main / /" \
  | sed 's/^/  /'
if grep -qE "^\[ci/$job\] +❌" "$log"; then
  echo
  echo "  what failed, in the job's own words:"
  grep -E -- '--- FAIL|_test\.go:[0-9]+: |^\[ci/[a-z]+\]   \| FAIL\s|signal: killed|panic:|::error::|exitcode' "$log" \
    | sed -E 's/^\[ci\/[a-z]+\]   \| ?//' | head -20 | sed 's/^/    /' | cut -c1-200
  if grep -q 'signal: killed' "$log"; then
    echo "    (signal: killed is the container's OOM killer; Docker Desktop's VM has $(docker info --format '{{.MemTotal}}' 2>/dev/null | awk '{printf "%.1f", $1/1073741824}') GiB — raise it in Settings → Resources, or lower KELYFOS_ACT_GOFLAGS)"
  fi
fi
echo "  ----   not run here: build job (Buildroot image), boot job (x86_64 microVM under KVM) — limactl shell kelyfos-dev -- dev/ci-local.sh --boot is the stand-in"
kept_log="$root/act-$job-$short.log"
cp "$log" "$kept_log"
if [ "$rc" -eq 0 ]; then
  echo "  job '$job' passed on $short under act — the committed workflow, run in a container; not a hosted run"
else
  echo "  job '$job' FAILED on $short under act (exit $rc)"
fi
echo "  log     $kept_log"
[ "$keep" -eq 1 ] && echo "  clone kept at $dir/src"
exit "$rc"
