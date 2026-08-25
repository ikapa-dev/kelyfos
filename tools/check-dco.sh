#!/usr/bin/env bash
# Every commit in a range carries a Developer Certificate of Origin sign-off
# (P6-29, D56).
#
#   tools/check-dco.sh <base> <head>
#
# **Why a range and not the whole history.** CONTRIBUTING.md has required a
# `Signed-off-by` line since v0.1 and not one commit before v1.0 carries one, so
# a check over `git log` would fail on every branch forever and be switched off
# within a day. History cannot be rewritten either: it would invalidate every
# clone and every commit hash PLAN.html cites. So enforcement starts where it can
# be true — at the commits a push or a pull request actually adds — and
# CONTRIBUTING.md says so in as many words rather than implying the rule was
# always kept.
#
# **Merge commits are exempt.** A merge is authored by whoever pressed the
# button, carries no new work, and GitHub's own merge commits cannot be signed
# by a contributor. The sign-off belongs on the commits that contain the change.
set -uo pipefail

base="${1:-}"
head="${2:-HEAD}"
if [ -z "$base" ]; then
  echo "usage: tools/check-dco.sh <base> <head>" >&2
  exit 2
fi

# A base that is not in this clone — a force-push, or the very first push of a
# branch — leaves nothing to compare against. Checking nothing is the honest
# answer there; inventing a range would check the wrong commits.
if ! git rev-parse --quiet --verify "$base^{commit}" >/dev/null 2>&1; then
  echo "the base commit $base is not in this clone, so there is no range to check"
  exit 0
fi

# --no-merges for the reason in the header.
mapfile -t commits < <(git rev-list --no-merges "$base..$head" 2>/dev/null)
if [ "${#commits[@]}" -eq 0 ]; then
  echo "no new non-merge commits in $base..$head"
  exit 0
fi

missing=0
for c in "${commits[@]}"; do
  author="$(git log -1 --format='%an <%ae>' "$c")"
  if git log -1 --format='%B' "$c" | grep -qiE '^\s*Signed-off-by:\s*.+<.+@.+>'; then
    continue
  fi
  echo "  MISSING  $(git log -1 --format='%h %s' "$c")"
  echo "           author: $author"
  missing=$((missing + 1))
done

if [ "$missing" -gt 0 ]; then
  cat >&2 <<'MSG'

Every commit needs a Signed-off-by line matching its author. It is the
Developer Certificate of Origin: your statement that you have the right to
submit this work under the project's license. CONTRIBUTING.md has the text and
why this project uses a sign-off rather than a CLA.

  git commit -s                 on the next one
  git commit --amend -s         to fix the last one
  git rebase --signoff <base>   for a whole branch

MSG
  exit 1
fi

echo "all ${#commits[@]} new commits carry a sign-off"
