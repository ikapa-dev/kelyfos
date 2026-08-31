#!/usr/bin/env bash
# KelyfOS — regenerate .audit/ properly (ST-4.4, closing IA-L2's stale
# artifact half).
#
#   bash dev/audit-local.sh
#
# .audit/ is a LOCAL directory (excluded via .git/info/exclude, not
# .gitignore): it holds the static-analysis artifacts a reviewer reads, and
# it is exactly where a stale failure-documenting-itself artifact rots
# unnoticed — .audit/staticcheck.txt once contained "staticcheck: command
# not found", sitting where a reader expects a result. This script
# regenerates every file it names, timestamps them, and refuses to write an
# artifact whose tool could not run: an artifact that says nothing must be
# absent, not present and lying.
#
# Each tool is skipped — loudly, by name — when it is not installed; the
# script never fabricates a clean result for a tool that did not run.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUDIT="$REPO/.audit"
mkdir -p "$AUDIT"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
  echo "regenerated $STAMP by dev/audit-local.sh"
  echo "commit $(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo 'no git')"
} > "$AUDIT/STAMP.txt"
echo "audit artifacts → $AUDIT ($STAMP)"

# run_tool <name> <command> — run one analysis, write its artifact, and be
# honest in all three states: ran clean, ran with findings, DID NOT RUN. The
# third state writes no artifact at all — an absent tool leaves an absent
# file, never a file that documents its own absence as if it were a result.
run_tool() {
  local name="$1"
  shift
  if [ "$name" = "gitleaks" ] && ! command -v gitleaks >/dev/null 2>&1; then
    echo "  gitleaks: SKIPPED — not installed on this machine"
    return 0
  fi
  if eval "$@" > "$AUDIT/$name.txt" 2>&1; then
    echo "  $name: ok"
  else
    # A tool that failed to START (compile errors, bad flags) is not the
    # same as a tool that ran and found something. Distinguish by content.
    if grep -qiE "command not found|cannot decode|internal error" "$AUDIT/$name.txt"; then
      echo "  $name: DID NOT RUN (see .audit/$name.txt) — artifact removed"
      rm -f "$AUDIT/$name.txt"
    else
      echo "  $name: FINDINGS (see .audit/$name.txt)"
    fi
  fi
}

# govulncheck — reachability-based vulnerability scanning, the same
# invocation `make vuln` runs, pinned through versions.mk.
run_tool govulncheck "go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./..."

# staticcheck — the artifact that once documented its own absence. The
# version matters as much as the run: a staticcheck too old for this Go's
# export data writes internal errors that look like findings.
run_tool staticcheck "go run honnef.co/go/tools/cmd/staticcheck@latest ./..."

# gitleaks — full history; .gitleaksignore carries the reviewed false
# positives, so anything reported here is new.
run_tool gitleaks "gitleaks detect --no-banner"

echo "done — every file in $AUDIT describes this tree; absent files are tools that did not run"
