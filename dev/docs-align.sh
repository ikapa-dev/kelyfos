#!/usr/bin/env bash
# KelyfOS — is the documentation still aligned with the repository?
#
#   bash dev/docs-align.sh            every check
#   bash dev/docs-align.sh --offline  skip the checks that need GitHub (gh)
#
# The generated half of the documentation has a drift gate in CI (F-D4). This
# is the checklist for the hand-written half: the statements one document makes
# about another, the counts that go stale when something is added, the headings
# that name a date where the release was meant, and the hosted workflows whose
# result a page reports on. Each check prints one of
#
#   FAIL  something a reader would be misled by; the script exits 1
#   WARN  could not be checked here, or worth a look
#   ok    checked, aligned
#   info  a fact for the person reading, not a verdict
#
# It is a dev script rather than a CI job on purpose: several checks need
# judgement (a README sentence quoted in a comment is stale only if the README
# changed meaning), and the one that regenerates the reference is Linux-only.
# The skill in .claude/skills/docs-align says what to do about each line.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
OFFLINE=0
[ "${1:-}" = "--offline" ] && OFFLINE=1

fails=0
fail() { printf 'FAIL  %s\n' "$*"; fails=$((fails + 1)); }
warn() { printf 'WARN  %s\n' "$*"; }
ok()   { printf 'ok    %s\n' "$*"; }
info() { printf 'info  %s\n' "$*"; }
section() { printf '\n== %s\n' "$*"; }

# Tracked Markdown only: the ignored audit reports and worktree notes are not
# documentation and their links are allowed to dangle.
mapfile -t MD < <(git ls-files '*.md' ':!buildroot/**')

# --- 1. relative links resolve ---------------------------------------------
section "relative links in tracked Markdown"
broken=0
for f in "${MD[@]}"; do
  dir="$(dirname "$f")"
  while IFS= read -r t; do
    [ -z "$t" ] && continue
    case "$t" in http://*|https://*|mailto:*|\#*) continue ;; esac
    t="${t%%#*}"
    [ -z "$t" ] && continue
    if [ ! -e "$dir/$t" ]; then
      fail "$f links to $t, which does not exist"
      broken=$((broken + 1))
    fi
  done < <(grep -oE '\]\([^) ]+\)' "$f" | sed -E 's/^\]\(//; s/\)$//' | sort -u)
done
[ "$broken" -eq 0 ] && ok "every relative link in ${#MD[@]} files resolves"

# --- 2. the cookbook's recipe count, everywhere it is quoted -----------------
section "recipe count"
markers="$(grep -c '<!-- recipe: [a-z0-9-]* -->' docs/cookbook.md)"
markers=$((markers - 1))   # the extractor's own "<!-- recipe: name -->" example
word="$(sed -n '3p' docs/cookbook.md | awk '{print tolower($1)}')"
info "docs/cookbook.md has $markers recipes and calls itself \"$word\" (its extractor checks that pair)"
while IFS= read -r line; do
  n="${line%%:*}"
  if ! printf '%s' "$line" | grep -qi "$word"; then
    fail "docs/README.md:$n quotes a recipe count that is not \"$word\": ${line#*:}"
  fi
done < <(grep -niE '\b(ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty(-[a-z]+)?|thirty(-[a-z]+)?|forty(-[a-z]+)?|[0-9]+) (complete, copy-pasteable )?recipes' docs/README.md)
grep -qE "### \`cookbook.md\` — $word things that work" docs/README.md \
  && ok "docs/README.md's inventory heading says $word" \
  || fail "docs/README.md's cookbook inventory heading does not say \"$word things that work\""

# --- 3. every document under docs/ is on the map ----------------------------
section "documentation map"
missing=0
for f in docs/*.md; do
  b="$(basename "$f")"
  [ "$b" = README.md ] && continue
  if ! grep -q "$b" docs/README.md; then
    fail "docs/README.md does not mention $b (add a row to the map and an inventory entry)"
    missing=$((missing + 1))
  fi
done
[ "$missing" -eq 0 ] && ok "every docs/*.md is named in docs/README.md"
# The llms set has its own test; run it here because it is fast and it is the
# other half of the same question.
if command -v go >/dev/null; then
  if go test ./tools/gendocs/ -run 'TestEveryDocumentUnderDocsIsInTheLLMsSet|TestLLMsIndexLinksResolve|TestLLMsReleaseComesFromTheNewestChangelogSection' >/dev/null 2>&1; then
    ok "every docs/*.md is in the llms set, and the release both llms files name is the changelog's newest"
  else
    fail "go test ./tools/gendocs/ — the llms set or its release line disagrees with the tree"
  fi
else
  warn "go is not installed here; the llms-set tests were not run"
fi

# --- 4. the changelog names every tag, and the docs name releases -------------
section "releases"
if python3 tools/changelog.py --check >/dev/null 2>&1; then
  ok "CHANGELOG.md has a section for every published tag"
else
  fail "python3 tools/changelog.py --check"
fi
newest="$(grep -m1 -E '^## v[0-9]' CHANGELOG.md | sed -E 's/^## (v[^ ]+) — ([0-9-]+).*/\1 (\2)/')"
info "newest changelog release: $newest"
if grep -q "The release this describes is $newest" llms-full.txt && grep -q "The newest release is $newest" llms.txt; then
  ok "llms.txt and llms-full.txt name $newest"
else
  fail "llms.txt / llms-full.txt do not name $newest — run make docs (Linux) and commit"
fi
while IFS= read -r line; do
  fail "docs/upgrading.md heading names a date where the release belongs: $line"
done < <(grep -nE '^## [0-9]+\..*\([0-9]{4}-[0-9]{2}-[0-9]{2}\)$' docs/upgrading.md)
grep -qE '^## [0-9]+\..*\([0-9]{4}-[0-9]{2}-[0-9]{2}\)$' docs/upgrading.md || ok "docs/upgrading.md sections name releases, not dates"
newest_tag="${newest%% *}"
while IFS= read -r line; do
  v="$(printf '%s' "$line" | grep -oE 'v[0-9]+(\.[0-9]+)*' | head -1)"
  if [ "$v" = "$newest_tag" ]; then
    ok "current-as-of claim names the newest release: ${line%%:*}"
  else
    fail "a page claims to be current as of $v, and the newest release is $newest_tag: $line"
  fi
done < <(grep -nE 'current as of v[0-9]|repository is at v[0-9]' README.md docs/*.md 2>/dev/null)
info "per-document **Status:** lines name the version a specification was written for; they are not release claims:"
grep -nE '^\*\*Status:\*\*' docs/*.md | cut -c1-120 | sed 's/^/      /'

# --- 5. what other files say the README says ---------------------------------
section "statements about the README (judgement: still true of the current README?)"
grep -rnE "README('s| says| admits| carries| publishes| now| table| status| quickstart)" \
  --include='*.md' --include='*.sh' --include='*.go' --include='*.yml' --include='*.py' \
  docs dev tools .github SECURITY.md CONTRIBUTING.md CHANGELOG.md 2>/dev/null \
  | grep -vE '^docs/(exam|launch)/|^docs/(roadmap|decisions|decisions-features)\.md|docs-audit' \
  | cut -c1-160 | sed 's/^/info  /'

# --- 6. the generated half ---------------------------------------------------
# Compared with what was on disk before the run, not with HEAD: an uncommitted
# documentation edit legitimately changes llms-full.txt, and the question here
# is whether the committed generated files are what the source produces now.
section "generated reference and llms files"
gen_digest() { cat docs/reference/*.md llms.txt llms-full.txt | shasum | cut -c1-12; }
regen_check() {
  local before after
  before="$(gen_digest)"
  if ! "$@" >/dev/null 2>&1; then fail "make docs failed ($*)"; return; fi
  after="$(gen_digest)"
  if [ "$before" = "$after" ]; then
    ok "make docs changes nothing ($*)"
  else
    fail "make docs changed the generated files — review and commit them"
    git status --porcelain -- docs/reference llms.txt llms-full.txt | sed 's/^/      /'
  fi
}
case "$(uname -s)" in
  Linux) regen_check make docs ;;
  *)
    # Captured rather than piped into grep -q: under pipefail, grep exiting
    # early sends limactl SIGPIPE and the pipeline reads as "not running".
    lima_state="$(command -v limactl >/dev/null && limactl list --json 2>/dev/null || true)"
    if printf '%s' "$lima_state" | grep -q '"name":"kelyfos-dev"[^}]*"status":"Running"'; then
      regen_check limactl shell kelyfos-dev -- bash -lc "cd '$REPO' && make docs"
    else
      warn "make docs is Linux-only and kelyfos-dev is not running; run it there before committing"
    fi ;;
esac

# --- 7. the assets and numbers a page reports on -----------------------------
section "recorded assets"
gif_date="$(git log -1 --format=%cs -- docs/media/demo.gif)"
host_date="$(git log -1 --format=%cs -- host)"
info "docs/media/demo.gif recorded $gif_date; host/ last changed $host_date"
[ "$gif_date" \< "$host_date" ] && warn "the demo predates the newest CLI change — re-record with 'bash dev/demo-record.sh --record' in kelyfos-dev if what it shows has changed"

section "hosted workflows"
if [ "$OFFLINE" -eq 1 ]; then
  warn "--offline: hosted workflow results not checked"
elif ! command -v gh >/dev/null; then
  warn "gh is not installed; hosted workflow results not checked"
else
  for w in ci cookbook repro-check security security-lab bench caps; do
    line="$(gh run list --workflow "$w.yml" --limit 1 --json status,conclusion,headSha,createdAt,event \
      -q '.[0] | select(. != null) | "\(if .status == "completed" then .conclusion else .status end) \(.headSha[0:7]) \(.createdAt[0:10]) \(.event)"' 2>/dev/null)"
    case "$w:$line" in
      *:""|*:null*) case "$w" in
              bench|caps) warn "$w.yml has no run in GitHub's retained history — the README's numbers cite it; dispatch with 'gh workflow run $w.yml'" ;;
              *) warn "$w.yml has no run in GitHub's retained history" ;;
            esac ;;
      *:success*) ok "$w.yml: $line" ;;
      cookbook:failure*|ci:failure*) fail "$w.yml: $line — the pages that say CI runs this are wrong until it is green" ;;
      *) warn "$w.yml: $line" ;;
    esac
  done
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "docs-align: no failures"
else
  echo "docs-align: $fails failure(s)"
  exit 1
fi
