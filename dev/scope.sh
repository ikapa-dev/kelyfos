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
# The directory is named "kelyfos-cache" and NOT after the suite, which is not
# a cosmetic choice. KELYFOS_CACHE appears in a run's own output -- the vsock
# path and the jail path are printed -- and several suites assert on that
# output. dev/accept-notify.sh checks that a run without --notify "does not
# mention notifications at all" with `grep -q notify quiet.log`; a cache at
# /tmp/kelyfos-accept-notify.XXXXXX put the word in the jail path and turned
# that check red, a failure caused entirely by the directory's name. The two
# words used here are the two the shared path $HOME/.cache/kelyfos already
# contributed, so no suite can start matching on a word it did not match
# before. The suite name goes in a file inside instead.
scope_init() {
  local name="${1:-suite}"
  # The cache to borrow the image from is whatever KELYFOS_CACHE already said,
  # and $HOME/.cache/kelyfos only when it said nothing. A relocated cache is a
  # supported configuration -- Makefile's `KELYFOS_CACHE ?= $(HOME)/.cache/kelyfos`
  # means `make image KELYFOS_CACHE=/data/kelyfos` puts the image there, and
  # `kelyfos doctor` advises pointing it at a roomier filesystem -- so reading
  # $HOME here would discard the caller's setting and then fail to find an image
  # for a reason that names nothing about the cause.
  SCOPE_SHARED_CACHE="${SCOPE_SHARED_CACHE:-${KELYFOS_CACHE:-$HOME/.cache/kelyfos}}"
  # Beside the shared cache, not in $TMPDIR, and that is a correctness choice
  # rather than a tidiness one. internal/sandbox/jail.go's linkInto hard-links
  # the rootfs into each jail "when the source is on the same filesystem, which
  # it is for everything KelyfOS builds -- images and jails both live under the
  # cache root -- and a copy otherwise", and says why it matters: "copying a
  # 128 MiB image per sandbox would make `fork -n 4` cost half a gigabyte".
  # Putting run/ under /tmp while out/ stays under $HOME breaks that invariant
  # silently on any host where /tmp is a separate filesystem -- tmpfs is the
  # systemd default on Fedora, Arch and Ubuntu 24.10+ -- so `dev/cookbook.sh`,
  # which forks, would copy 128 MiB into RAM per machine and nothing would say
  # so. SCOPE_TMPDIR overrides for anyone who wants it elsewhere.
  SCOPE_ROOT="$(mktemp -d "${SCOPE_TMPDIR:-$(dirname "$SCOPE_SHARED_CACHE")}/kelyfos-cache.XXXXXX")"
  # Loudly, and not `|| return 1`. No caller checked that, and the consequence
  # of carrying on is the exact silent failure D79 names: KELYFOS_CACHE stays
  # unset, sandbox.Root() falls back to the SHARED cache, every guard in this
  # file short-circuits on the empty variable, the teardown kills nothing and
  # still returns 0, and the suite runs against everybody's cache and reports
  # PASS.
  if [ -z "${SCOPE_ROOT:-}" ] || [ ! -d "$SCOPE_ROOT" ]; then
    printf 'scope: could not create a private cache beside %s; refusing to run against the shared one\n' \
      "$SCOPE_SHARED_CACHE" >&2
    exit 1
  fi
  printf '%s\n' "$name" > "$SCOPE_ROOT/.suite" 2>/dev/null
  if [ -d "$SCOPE_SHARED_CACHE/out" ]; then
    ln -s "$SCOPE_SHARED_CACHE/out" "$SCOPE_ROOT/out"
  else
    printf 'scope: no guest image at %s/out -- run `make image FLAVOR=dev` first\n' \
      "$SCOPE_SHARED_CACHE" >&2
  fi
  export KELYFOS_CACHE="$SCOPE_ROOT"
}

# This run's own Firecracker pids, read from the run directories under its own
# cache. Read them while the machines still exist: teardown removes the
# directory that holds them.
#
# TWO sources, and the second is not optional. firecracker.pid is written by the
# *jailer*, not by KelyfOS -- internal/sandbox/jail.go:210 is the only writer,
# and sandbox.go says it outright: "Absent or unreadable is not an error:
# --no-jail writes none." So a run started with --no-jail has no pid file, and a
# teardown that reads only that file walks straight past the machine and reports
# success having killed nothing. That is the silent failure D79 warns this fix
# could itself become, and it is not hypothetical: dev/accept-jail.sh and
# dev/accept-seccomp.sh both boot --no-jail deliberately, so those are exactly
# the machines this has to find.
#
# The unjailed pid is in the sandbox's own state file: sandbox.go:701 sets
# State.PID from cmd.Process.Pid, and it lands as "pid" in sandbox.json, which
# sits either beside the jail directory or inside it depending on the path. Both
# are read, and the pids are de-duplicated because a jailed sandbox has both.
# The jailer writes firecracker.pid with NO trailing newline, so `cat`-ing two
# of them in a row yields "111222" -- one token that is not a pid, which a
# teardown then fails to kill while reporting nothing wrong. Every read here
# goes through this, which strips whatever framing a file has and emits one pid
# per line.
scope_emit_pid() {
  local raw
  raw="$(tr -dc '0-9' < "$1" 2>/dev/null)"
  [ -n "$raw" ] && [ "$raw" != "0" ] && printf '%s\n' "$raw"
  return 0
}

# The "pid" field of a sandbox.json, on its own line.
scope_emit_state_pid() {
  local raw
  raw="$(sed -n 's/.*"pid"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$1" 2>/dev/null | sed -n 1p)"
  [ -n "$raw" ] && [ "$raw" != "0" ] && printf '%s\n' "$raw"
  return 0
}

scope_pids() {
  local d
  [ -n "${KELYFOS_CACHE:-}" ] || return 0
  {
    for d in "$KELYFOS_CACHE"/run/firecracker/*/; do
      [ -d "$d" ] || continue
      scope_pids_in "$d"
    done
  } | sort -u
}

# scope_live_pids — this run's Firecracker pids that are actually running.
#
# scope_pids reads pid files, and a sandbox that was killed rather than shut
# down leaves its file behind; a zombie also still answers kill -0, so the
# state field in /proc/<pid>/stat is what separates a machine from its corpse.
#
# This is what replaces `pgrep -n firecracker` where a suite wanted "the VMM I
# just booted". That idiom asks the host for its newest Firecracker, which on a
# shared machine is a peer's -- so the suite would go on to read a stranger's
# /proc/<pid>/mountinfo and /proc/<pid>/cgroup and check ITS jail, passing or
# failing on a machine it did not start.
# scope_newest_pid — the machine this run started most recently, which is what
# `pgrep -n firecracker` meant before it was replaced. scope_pids sorts, so
# `scope_live_pids | head -1` is an arbitrary sandbox rather than the newest one
# whenever two of this run's machines are live at once, and the checks that use
# it go on to read that pid's cgroup and mountinfo.
scope_newest_pid() {
  local d newest="" p
  [ -n "${KELYFOS_CACHE:-}" ] || return 0
  # Newest by the run directory's own mtime, the same way accept-profile.sh
  # already picks a state file with `ls -t`.
  for d in $(ls -td "$KELYFOS_CACHE"/run/firecracker/*/ 2>/dev/null); do
    for p in $(KELYFOS_CACHE="$KELYFOS_CACHE" scope_pids_in "$d"); do
      if scope_is_live "$p"; then newest="$p"; break; fi
    done
    [ -n "$newest" ] && break
  done
  [ -n "$newest" ] && echo "$newest"
}

# The pids recorded under one run directory, both sources (see scope_pids).
scope_pids_in() {
  local d="$1" f
  {
    [ -f "$d/root/firecracker.pid" ] && scope_emit_pid "$d/root/firecracker.pid"
    for f in "$d/sandbox.json" "$d/root/sandbox.json"; do
      [ -f "$f" ] || continue
      scope_emit_state_pid "$f"
    done
  } | sort -u
}

scope_is_live() {
  local p="$1" st
  [ -e "/proc/$p/stat" ] || return 1
  st="$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)"
  [ -n "$st" ] && [ "$st" != "Z" ]
}

scope_live_pids() {
  local p st
  for p in $(scope_pids); do
    [ -e "/proc/$p/stat" ] || continue
    st="$(awk '{print $3}' "/proc/$p/stat" 2>/dev/null)"
    [ -n "$st" ] && [ "$st" != "Z" ] && echo "$p"
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

# scope_kill_kelyfos [subcommand...] — stop this run's kelyfos processes and
# nobody else's. The mid-run equivalent of the `pkill -f "kelyfos run"` these
# suites used between steps, which matched a peer's run and the suite's own
# shell too.
#
# The subcommands matter and are not decoration. `pkill -f "kelyfos run"` kills
# a `kelyfos run` and leaves a `kelyfos snapshot restore` alone, and at least
# one suite depends on exactly that: dev/accept-profile.sh's halt() is called
# after a restore and the machine that restore brought up has to survive it,
# because the checks below exec into it. Killing every kelyfos process this run
# owns is right for the EXIT teardown and wrong here -- it took the restored
# machine down and two checks then failed with "no running sandbox". So a
# caller that used to name a subcommand names it still; with no argument every
# kelyfos process carrying this run's cache is stopped.
scope_kill_kelyfos() {
  local p sub want argv1
  for p in $(scope_own_kelyfos_pids); do
    if [ "$#" -gt 0 ]; then
      # The subcommand is kelyfos' FIRST argument, so match it there rather
      # than anywhere in the command line. `grep -qw run` also matches a path
      # component -- `kelyfos fork --workspace /srv/run/x` would answer to
      # "run" -- and treats its argument as a regex. This is the mechanism that
      # keeps `halt` from killing a `kelyfos snapshot restore`, so it is worth
      # being exact about.
      want=""
      argv1="$(tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | sed -n 2p)"
      for sub in "$@"; do
        if [ "$argv1" = "$sub" ]; then
          want=yes
          break
        fi
      done
      [ -n "$want" ] || continue
    fi
    kill "$p" 2>/dev/null
  done
}

# scope_wait_kelyfos_gone [seconds] — wait for this run's own kelyfos processes
# to exit. Replaces `pgrep -f "kelyfos run"` used as a wait condition, which on
# a shared host waits on a peer's run and times out for a reason that has
# nothing to do with this suite.
scope_wait_kelyfos_gone() {
  local i limit="${1:-30}"
  shift 2>/dev/null || true
  for i in $(seq 1 "$limit"); do
    if [ "$#" -gt 0 ]; then
      # Wait only for the subcommands this halt actually signalled; a process
      # it deliberately left running must not hold the loop for its full limit.
      local p sub still="" a1
      for p in $(scope_own_kelyfos_pids); do
        a1="$(tr '\0' '\n' < "/proc/$p/cmdline" 2>/dev/null | sed -n 2p)"
        for sub in "$@"; do
          [ "$a1" = "$sub" ] && still=yes
        done
      done
      [ -z "$still" ] && return 0
    else
      [ -z "$(scope_own_kelyfos_pids)" ] && return 0
    fi
    sleep 1
  done
  return 1
}

# scope_kill_machines — stop this run's kelyfos processes, then its machines,
# and leave the cache in place. This is the mid-run form: several suites stop
# everything between steps and keep going, and a teardown that removed the
# cache underneath them would take the sessions they are about to read.
#
# The pids are collected BEFORE anything is signalled, because a `kelyfos run`
# that is shutting down removes the run directory the Firecracker pid is read
# from, and a teardown that reads them afterwards finds an empty list and
# reports success having killed nothing.
scope_kill_machines() {
  local fc_pids p left
  fc_pids="$(scope_pids)"

  # Any subcommands given are passed straight through, so a caller that used to
  # name the ones it killed keeps naming them (see scope_kill_kelyfos).
  scope_kill_kelyfos "$@"
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
  return 0
}

# scope_teardown — the trap cleanup EXIT form: stop everything this run started
# and take its cache with it.
scope_teardown() {
  scope_kill_machines "$@"
  scope_remove_cache
  return 0
}

# The jailer leaves root-owned files behind -- the pid file, and a copy of the
# host's CPU topology under sys/ -- and internal/sandbox/jail.go says what a
# plain removal does about it: "A plain RemoveAll fails half way and leaves the
# rest, which over a few hundred runs is a disk full of abandoned chroots." That
# is why removeJail falls back to sudo. Without the same fallback this change
# would be a regression on tidiness rather than an improvement: the leftovers
# used to pile up in one well-known shared cache, and would now be anonymous
# part-removed chroots under a fresh /tmp directory per run, with the .suite
# breadcrumb naming the culprit deleted first because it is the one file we own.
scope_remove_cache() {
  [ -n "${SCOPE_ROOT:-}" ] || return 0
  case "$(basename "$SCOPE_ROOT")" in
    kelyfos-cache.??????) ;;
    *) return 0 ;;   # never rm -rf something this function did not create
  esac
  rm -rf "$SCOPE_ROOT" 2>/dev/null
  if [ -d "$SCOPE_ROOT" ]; then
    sudo -n rm -rf "$SCOPE_ROOT" 2>/dev/null
  fi
  if [ -d "$SCOPE_ROOT" ]; then
    printf '  scope: could not remove %s (root-owned jailer leftovers; sudo -n unavailable)\n' \
      "$SCOPE_ROOT" >&2
  fi
}
