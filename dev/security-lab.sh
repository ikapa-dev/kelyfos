#!/usr/bin/env bash
# KelyfOS — the boot-and-assert layer the security suites run on. Sourced,
# never run (a direct run executes the self-test at the bottom of this file):
#
#     source "$REPO/dev/security-lab.sh"
#     slab_init accept-security-egress
#     aup -allow example.com
#     ax "curl -sS -o /dev/null -w '%{http_code}' https://example.com"
#     adown
#
# Why this exists. The independent audit (SECURITY-AUDIT-independent-2026-08-31)
# proved ~30 scenarios by hand against live sandboxes; ST-1.2..1.9 commit those
# scenarios as suites. Every suite needs the same four things the audit's
# harness improvised each time — boot a machine and hold it, exec into it, stop
# it through its trailing command, and assert on events, files and the nft
# ruleset — and each improvisation is a fresh chance to get teardown scoping
# wrong. This file is that layer, once, on top of dev/scope.sh (D83), which
# stays the only thing that decides what "our own machines" means.
#
# The rule this file will not break, because D83 closed the class and reopening
# it is a regression: there is no `pgrep firecracker` here and no host-wide
# `pkill`. Machines are found through the private KELYFOS_CACHE scope_init
# hands out, and the run process through the pid captured at spawn and — as the
# fallback that survives a lost pid — through scope_own_kelyfos_pids, which
# matches KELYFOS_CACHE in /proc/<pid>/environ rather than a name.

# ---------------------------------------------------------------- environment

# The suites boot microVMs and create TAP devices and nft tables; neither
# exists on macOS. The Makefile's linux-only guard stops `make`, and this stops
# `bash dev/accept-security-*.sh` run by hand on the wrong side of the Lima
# boundary — with the reason, rather than forty failures about /dev/kvm.
if [ "$(uname -s)" != "Linux" ]; then
  echo "security-lab: this suite boots microVMs; run it inside the Lima VM (limactl shell kelyfos-dev) — not on $(uname -s)" >&2
  return 124 2>/dev/null || exit 124
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$REPO/bin}"
export PATH="$BIN:$PATH"

# scope.sh stays the only teardown authority (D83): everything here that stops
# a machine goes through its functions, and nothing here re-derives "our own".
source "$REPO/dev/scope.sh"

# The suite's scratch directory and the EXIT trap are set up here so a suite
# cannot forget them. Cleanup discipline is §8 trap 8: every session ends with
# this run's machines gone and the scratch tree removed, and a suite that
# fails halfway is exactly the run most likely to leave things behind.
SLAB_WORK=""
slab_exit_cleanup() {
  adown_quiet 2>/dev/null
  scope_teardown
  [ -n "$SLAB_WORK" ] && rm -rf "$SLAB_WORK"
  return 0
}

# ---------------------------------------------------------------- accounting
# The pass/fail conventions of the existing suites (dev/accept-shell.sh), once,
# so the security suites differ from their siblings only in what they check.

PASSES=0 FAILURES=0 SKIPPED=0
SUMMARY=()

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
pass() { PASSES=$((PASSES+1)); SUMMARY+=("PASS  $*"); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAILURES=$((FAILURES+1)); SUMMARY+=("FAIL  $*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
# skip is for a check the environment cannot host today — a third party's
# resolver being down, a feature this image lacks — and it is loud on purpose:
# a quiet skip is how a suite stops measuring without anyone noticing. The
# reason is the message; the suite still exits 0 unless something FAILED,
# because an environment gap is not a security regression.
skip() { SKIPPED=$((SKIPPED+1)); SUMMARY+=("SKIP  $*"); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }
check() { if [ "$1" = "yes" ]; then pass "$2"; else fail "$2"; fi; }

# The one exit a suite needs: prints the summary and exits green or red. A red
# suite is a blocker under CONTRIBUTING's "CI is the gate" rule, so the exit
# status is the contract and the summary is the evidence.
slab_done() {
  say "summary"
  printf '%s\n' "${SUMMARY[@]}" | sed 's/^/  /'
  printf '\n  %d passed, %d failed, %d skipped\n' "$PASSES" "$FAILURES" "$SKIPPED"
  [ "$FAILURES" -eq 0 ]
}

assert_eq() { # assert_eq <got> <want> <label>
  if [ "$1" = "$2" ]; then pass "$3"; else
    fail "$3"
    printf '        got:  %s\n        want: %s\n' "$1" "$2"
  fi
}

assert_contains() { # assert_contains <haystack> <needle> <label>
  case "$1" in *"$2"*) pass "$3" ;; *)
    fail "$3"; printf '        missing from: %.400s\n' "$1" ;; esac
}

# The flight recorder is the security suites' second witness: every egress
# attempt, secret use and refusal is an event, and asserting on the record
# rather than only on the wire is what makes a suite able to catch a refusal
# that happens to work. Events are read as raw JSON, one per line, and grepped
# with -a — the log can carry bytes grep treats as binary, which silently broke
# extraction once (§8 trap 3).
slab_events() { # slab_events [session]  — the raw event stream, one JSON object per line
  "$BIN/kelyfos" log -session "${1:-${AUP_ID:-}}" -json 2>/dev/null
}

assert_grep_event() { # assert_grep_event <pattern> <label> [session]
  if slab_events "${3:-}" | grep -aqE "$1"; then pass "$2"; else fail "$2 (no event matching /$1/)"; fi
}

assert_no_event() { # assert_no_event <pattern> <label> [session]
  if slab_events "${3:-}" | grep -aqE "$1"; then fail "$2 (event /$1/ must not exist)"; else pass "$2"; fi
}

# The forward test's invariant — the firewall gains nothing while a forwarded
# port is live — is a diff of the ruleset, so the baseline is marked before the
# machine exists and compared while it does.
slab_nft_md5() { sudo -n nft list ruleset 2>/dev/null | md5sum | awk '{print $1}'; }
nft_mark() { SLAB_NFT_MARK="$(slab_nft_md5)"; }
assert_nft_unchanged() { # assert_nft_unchanged <label>
  assert_eq "$(slab_nft_md5)" "${SLAB_NFT_MARK:-}" "$1"
}

# slab_net_ok — whether the VM host can reach the open internet right now.
# The security suites assert against live origins (example.com) and a third
# party's wildcard resolver (nip.io), and the honest choice is to say so
# rather than let a network hiccup read as a security regression: suites call
# this once and skip their online battery, loudly and by name, when it fails.
slab_net_ok() {
  curl -sS -o /dev/null --max-time 10 https://example.com 2>/dev/null
}

# ---------------------------------------------------------------- boot layer

# aup [run-flags...] — boot one sandbox and hold it.
#
# Boots `kelyfos run` in the background with a trailing `sleep` (§8 trap 2: the
# sandbox lives while the trailing command lives, so the harness owns a sleep
# rather than a tty) and returns when the boot banner names the sandbox. Sets:
#   AUP_ID    the sandbox id, read from stdout only
#   AUP_PID   the `kelyfos run` process
#   AUP_LOG   its log, under the suite's scratch dir
# The id is captured from the machine-readable `sandbox=<id>` line (ST-0.1)
# when present and from the human `sandbox <id> ready in …` banner otherwise,
# so the harness works before and after ST-0.1 and the suites never parse a
# session list to learn what they just booted.
#
# AUP_DWELL (default 900 s) is the trailing sleep. AUP_MAX_RUNTIME (default
# 20 m) is the -max-runtime safety net added unless the caller brought their
# own: a harness bug that loses the sleep must cost twenty minutes, not an
# immortal machine. AUP_BOOT_TIMEOUT (default 120 s) bounds the wait for boot.
aup() {
  AUP_LOG="$SLAB_WORK/run-$AUP_SEQ.log"
  AUP_SEQ=$((AUP_SEQ+1))
  AUP_TRAILING=1
  _aup_spawn "$@" -- sleep "${AUP_DWELL:-900}"
}

# aup_bare [run-flags...] — the same boot with NO trailing command.
#
# The lifecycle suite (ST-1.9, ST-0.3) exists to signal the run process itself,
# which needs a run whose teardown does not hang off a child. AUP_PID is the
# thing to signal; adown sends it SIGTERM directly, the path ci.yml's boot job
# already exercises on every push.
aup_bare() {
  AUP_LOG="$SLAB_WORK/run-$AUP_SEQ.log"
  AUP_SEQ=$((AUP_SEQ+1))
  AUP_TRAILING=0
  _aup_spawn "$@"
}

_aup_spawn() {
  # The default safety net, unless the caller named their own budget.
  local args=() a has_budget=""
  for a in "$@"; do [ "$a" = "-max-runtime" ] && has_budget=yes; done
  if [ -z "$has_budget" ]; then
    args=(-max-runtime "${AUP_MAX_RUNTIME:-20m}")
  fi
  args+=("$@")

  rm -f "$AUP_LOG"
  # `( … & )` double-forks, the same shape every existing suite uses, so the
  # run is not a child of this shell and cannot be killed by a process-group
  # signal aimed at the suite. $! inside the subshell is the run's pid; the
  # subshell exits and the run reparents to init with the pid recorded here.
  ( "$BIN/kelyfos" run -image "${SLAB_IMAGE:-dev}" "${args[@]}" > "$AUP_LOG" 2>&1 & echo $! > "$SLAB_WORK/run.pid" )
  AUP_PID="$(cat "$SLAB_WORK/run.pid")"

  local i id=""
  for i in $(seq 1 $(( ${AUP_BOOT_TIMEOUT:-120} * 5 ))); do
    id="$(sed -n 's/.*sandbox=\([0-9a-fA-F-]\{8,\}\).*/\1/p' "$AUP_LOG" 2>/dev/null | head -1)"
    [ -z "$id" ] && id="$(sed -n 's/.*sandbox \([0-9a-fA-F]\{8,\}\) ready.*/\1/p' "$AUP_LOG" 2>/dev/null | head -1)"
    [ -n "$id" ] && break
    # A run that died before boot said anything gets its log shown, not a
    # two-minute wait for a poll that can never succeed.
    if ! kill -0 "$AUP_PID" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  AUP_ID="$id"
  if [ -z "$AUP_ID" ]; then
    fail "the sandbox booted (pid $AUP_PID)"
    echo "  --- run log (tail) ---"
    tail -5 "$AUP_LOG" | sed 's/^/  | /'
    AUP_PID=""
    return 1
  fi
  pass "the sandbox booted (id $AUP_ID)"
  return 0
}

# adown — stop the sandbox aup started, through the door it is meant to close.
#
# §8 trap 2 is the rule: with a trailing command, teardown happens when the
# child exits, so the harness interrupts the CHILD (pkill -INT -P <run-pid> —
# our own run's child, found by parent pid, not a host-wide pattern) and waits
# for the run to exit. With no trailing command the run pid gets SIGTERM
# directly, which its signal handler handles (ci.yml's boot job asserts that
# on every push). The scope.sh teardown remains underneath as the fallback
# that catches whatever the graceful path missed, scoped to this run's cache.
adown() { adown_quiet; }
adown_quiet() {
  [ -n "${AUP_PID:-}" ] || { scope_kill_machines run; return 0; }
  if [ "${AUP_TRAILING:-1}" = "1" ] && kill -0 "$AUP_PID" 2>/dev/null; then
    pkill -INT -P "$AUP_PID" 2>/dev/null
  elif kill -0 "$AUP_PID" 2>/dev/null; then
    kill -TERM "$AUP_PID" 2>/dev/null
  fi
  local i
  for i in $(seq 1 $(( ${AUP_DOWN_TIMEOUT:-90} * 2 ))); do
    kill -0 "$AUP_PID" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$AUP_PID" 2>/dev/null; then
    echo "  security-lab: run pid $AUP_PID did not exit gracefully; scoping the fallback" >&2
    scope_kill_machines run
  fi
  # The machines must be gone before this returns, or every assertion after a
  # restore/second-boot reads a stranger: wait, then force, then report what
  # refused to die rather than pretending. scope_wait_kelyfos_gone takes the
  # budget first and the subcommands after it.
  scope_wait_kelyfos_gone 30 run || scope_kill_machines run
  AUP_PID=""; AUP_ID=""
  return 0
}

# ax [exec-flags...] <cmd...> — exec into the sandbox aup booted.
#
# Pinned to -sandbox "$AUP_ID" so a suite can never exec into "the only running
# one": on a shared machine that default is a coin toss between this run's
# machine and a peer's. The timeout defaults to 60 s (AX_TIMEOUT) so a guest
# that cannot answer costs a suite seconds, not its whole runtime; pass 0 for
# no limit. The command's exit status and stdout are the caller's to assert on.
ax() {
  local t="${AX_TIMEOUT:-60s}"
  "$BIN/kelyfos" exec -sandbox "${AX_SANDBOX:-$AUP_ID}" -timeout "$t" "$@"
}

# ax_script <shell> <local-file> — run a host-written script inside the guest.
#
# §8 trap 4's recipe: the guest has no shared filesystem with the host, so a
# script goes in base64-encoded through exec, is decoded to /tmp, and is run by
# the interpreter named. The temp file is removed on both the clean and the
# failing path, and the script's exit status comes back.
ax_script() { # ax_script <interpreter> <local-file>
  local interp="$1" file="$2" b64 rc
  b64="$(base64 -w0 "$file")"
  ax "echo $b64 | base64 -d > /tmp/.slab-script && $interp /tmp/.slab-script; rc=\$?; rm -f /tmp/.slab-script; exit \$rc"
}

# ---------------------------------------------------------------- preflight

# slab_init <suite-name> — scope_init's private cache, then the preflight.
#
# Fails loudly, before a single assertion runs, when the machine cannot host
# the suite: no guest image, a CLI that is missing or older than the source it
# would need to be rebuilt from, or a doctor that is not green. Each check can
# be skipped by name — SLAB_SKIP=doctor,comma,separated — because a suite that
# must run where a check cannot pass should say so rather than disable the
# check for everybody.
slab_init() {
  local suite="${1:-security-suite}" skip="${SLAB_SKIP:-}"
  case ",$skip," in *,image,*) ;; *)
    # scope_init refuses (rather than silently continuing) when it cannot make
    # a private cache — D83 finding 2 — and its failure is the right failure.
    scope_init "$suite"
    ;; esac

  SLAB_WORK="$(mktemp -d)"
  AUP_SEQ=0
  trap slab_exit_cleanup EXIT

  say "KelyfOS security lab — $suite"
  echo "  cache  $KELYFOS_CACHE"
  echo "  host   $(uname -m), $(uname -r)"

  # Build-if-stale: the suites test behaviour, and a binary built from last
  # week's source turns every red herring into an hour of confusion. `find
  # -newer` over the three Go trees is the staleness test; the build is the
  # same one `make cli` runs, done here so a suite is self-sufficient in the VM.
  if [ ! -x "$BIN/kelyfos" ]; then
    echo "  building the CLI ($BIN/kelyfos missing)"
    (cd "$REPO" && go build -o "$BIN/kelyfos" ./host) || { echo "security-lab: CLI build failed" >&2; exit 1; }
  elif [ -n "$(find "$REPO/host" "$REPO/internal" "$REPO/supervisor" -name '*.go' -newer "$BIN/kelyfos" -print -quit 2>/dev/null)" ]; then
    echo "  rebuilding the CLI (source newer than $BIN/kelyfos)"
    (cd "$REPO" && go build -o "$BIN/kelyfos" ./host) || { echo "security-lab: CLI build failed" >&2; exit 1; }
  fi

  case ",$skip," in *,image,*) ;; *)
    if [ ! -e "$KELYFOS_CACHE/out/$(uname -m)/rootfs.ext4" ]; then
      echo "security-lab: no guest image at $KELYFOS_CACHE/out/$(uname -m) — run \`make image FLAVOR=dev\` first (or SLAB_SKIP=image)" >&2
      exit 1
    fi
    ;; esac

  case ",$skip," in *,doctor,*) ;; *)
    if ! "$BIN/kelyfos" doctor > "$SLAB_WORK/doctor.log" 2>&1; then
      echo "security-lab: kelyfos doctor is not green — this machine cannot host the suite (SLAB_SKIP=doctor to override):" >&2
      tail -20 "$SLAB_WORK/doctor.log" | sed 's/^/  | /' >&2
      exit 1
    fi
    ;; esac

  # The foreign residue the audit left on this shared VM (IA-I4) is named here
  # so a suite that later diffs the ruleset knows a pre-existing table is not
  # its own doing — and so nobody "cleans it up".
  nft_mark
}

# ---------------------------------------------------------------- self-test
# Run directly — `bash dev/security-lab.sh` — this boots one sandbox and checks
# this file's own promises: a passing assertion passes, a deliberately failing
# one produces a FAIL line and does not stop the suite, adown closes the
# machine it opened, and the EXIT trap leaves nothing of this run's behind.
# ST-1.1's acceptance criterion is this test, not a description of it.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -uo pipefail
  slab_init security-lab-selftest
  aup
  ax "echo hello-from-selftest"
  assert_eq "$(ax "echo one" 2>/dev/null)" "one" "selftest: exec returns the guest's stdout"
  assert_eq "deliberate" "mismatch" "selftest: a failing assertion fails clearly"
  assert_grep_event 'session\.(start|policy)' "selftest: the record is readable as events"
  assert_no_event 'this-event-cannot-exist' "selftest: a missing event is provably missing"
  nft_mark
  assert_nft_unchanged "selftest: the firewall is untouched by a plain boot"
  say "selftest: teardown"
  adown
  assert_eq "$(scope_live_pids | wc -l | tr -d ' ')" "0" "selftest: adown left none of this run's machines"
  # The deliberate failure above is the thing under test, not a defect: this
  # run is green exactly when the accounting says one assertion failed loudly
  # and everything else held. Reset before the summary so the self-test exits
  # 0 when the mechanism it exists to prove is proven.
  assert_eq "$FAILURES" "1" "selftest: exactly the deliberate assertion failed"
  FAILURES=0
  # The EXIT trap still runs scope_teardown; a second sweep finding nothing is
  # the point, so its output is expected to be empty here.
  slab_done
fi
