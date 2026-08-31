# KelyfOS — a dev suite's own cache, and a teardown that kills only its own
# machines. Sourced, never run:
#
#     source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scope.sh"
#     scope_init accept-shell
#     cleanup() { scope_teardown; rm -rf "$WORK"; }
#     trap cleanup EXIT
#
# Why this exists. These suites used to end with
#
#     for p in $(pgrep firecracker 2>/dev/null); do kill "$p" 2>/dev/null; done
#
# which is a host-wide question answered with a kill: it does not ask whether
# THIS run's sandboxes are gone, it asks whether any Firecracker is running
# anywhere, and it kills whatever it finds. On a machine where several agent
# worktrees are working at once — which is how this project is built — that is
# a peer's microVMs. It is the fourth instance of the class P7-16 closed in
# product code, it is recorded as D79's deferral, and the cost is dated: while
# dev/cookbook.sh was running, a reviewing agent's `make test` went red with
# three internal/sandbox integration failures, "firecracker exited before the
# guest was ready: signal: terminated". Neither party did anything wrong.
#
# The fix is S20's shape generalised (0b3dfb8, and dev/prove-two-teams.sh and
# dev/demo-team.sh are the worked examples): stop asking "is any Firecracker
# running on this host" and start asking "are this run's own sandboxes gone",
# by reading the pids out of the run directories the sandboxes themselves
# wrote. Giving the run its own KELYFOS_CACHE is what makes "its own"
# answerable — sandbox.Root() reads that variable, so every run directory this
# suite creates is under it, and no directory under it belongs to anybody else.
#
# The failure mode to keep in mind while editing this file: a wrong scoping
# here does not fail loudly. It silently stops killing anything, the suite
# still reports PASS, and the leak poisons every run after it. That is why
# scope_teardown reports what it could not kill instead of staying quiet.

# scope_init <suite-name>
#
# Gives this run a private KELYFOS_CACHE. The one thing it must NOT have its own
# copy of is the guest image: sandbox.ImageDir is Root()/out/<arch>, `make
# image` takes about thirty-five minutes on a cold machine, and out/ is
# read-only to everything but that — so it is shared by symlink and every
# writable thing under the cache is this run's alone.
scope_init() {
  local name="${1:-suite}"
  SCOPE_SHARED_CACHE="${SCOPE_SHARED_CACHE:-$HOME/.cache/kelyfos}"
  SCOPE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/kelyfos-${name}.XXXXXX")" || return 1
  if [ -d "$SCOPE_SHARED_CACHE/out" ]; then
    ln -s "$SCOPE_SHARED_CACHE/out" "$SCOPE_ROOT/out"
  fi
  export KELYFOS_CACHE="$SCOPE_ROOT"
}

# This run's own Firecracker pids, read from the run directories under its own
# cache — the same jail run-directory shape internal/sandbox.jailRunDir builds,
# and the same file S20 taught dev/demo-team.sh to read. Read them while the
# machines still exist: teardown removes the directory that holds the pid file.
scope_pids() {
  local f
  [ -n "${KELYFOS_CACHE:-}" ] || return 0
  for f in "$KELYFOS_CACHE"/run/firecracker/*/root/firecracker.pid; do
    [ -f "$f" ] || continue
    cat "$f" 2>/dev/null
  done
}

# The kelyfos processes belonging to THIS run, identified by the private cache
# in their environment rather than by their name.
#
# `pkill -f "kelyfos run"` is the same host-wide question as `pgrep
# firecracker`, one layer up: it matches a peer worktree's run just as happily,
# and it matches the shell running this suite too, which is how a careless
# cleanup kills itself. Matching on the environment cannot do either — a peer
# has a different KELYFOS_CACHE, and /proc/<pid>/environ is readable only for
# this user's own processes, which is exactly the set we are entitled to kill.
#
# It also survives the `( kelyfos run & )` double-fork these suites use, which
# reparents the process to init and puts it out of reach of a process-tree walk.
scope_own_kelyfos_pids() {
  local p
  [ -n "${KELYFOS_CACHE:-}" ] || return 0
  for p in $(pgrep -x kelyfos 2>/dev/null); do
    [ -r "/proc/$p/environ" ] || continue
    if tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null \
       | grep -qxF "KELYFOS_CACHE=$KELYFOS_CACHE"; then
      echo "$p"
    fi
  done
}

# scope_teardown — stop this run's kelyfos processes, then its machines.
#
# The pids are collected BEFORE anything is signalled, because a `kelyfos run`
# that is shutting down removes the run directory the Firecracker pid is read
# from, and a teardown that reads them afterwards finds an empty list and
# reports success having killed nothing.
scope_teardown() {
  local fc_pids p left
  fc_pids="$(scope_pids)"

  for p in $(scope_own_kelyfos_pids); do kill "$p" 2>/dev/null; done
  sleep 1
  for p in $fc_pids; do kill "$p" 2>/dev/null; done
  sleep 1

  # Say what survived. A scoping bug here is silent by nature: it stops killing
  # anything and the suite still passes. This line is what makes it audible.
  left=""
  for p in $fc_pids; do
    if [ -e "/proc/$p/stat" ] && [ "$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)" != "Z" ]; then
      left="$left $p"
    fi
  done
  if [ -n "$left" ]; then
    printf '  scope: this run left Firecracker pids alive:%s\n' "$left" >&2
    for p in $left; do kill -9 "$p" 2>/dev/null; done
  fi

  [ -n "${SCOPE_ROOT:-}" ] && rm -rf "$SCOPE_ROOT" 2>/dev/null
  return 0
}
