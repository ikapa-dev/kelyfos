---
name: docs-align
description: Check that KelyfOS's documentation still matches the repository and fix what drifted — after a release, after adding a document or a cookbook recipe, after changing the README, or when asked whether the docs are up to date.
---

# docs-align

The generated half of the documentation (`docs/reference/`, `llms.txt`,
`llms-full.txt`) has a CI drift gate. This skill covers the hand-written half:
what one document says about another, counts that go stale when something is
added, headings that name a date where a release was meant, and the hosted
workflows whose results a page reports on.

## 1. Run the checker

```sh
bash dev/docs-align.sh            # everything; needs gh for the hosted-workflow part
bash dev/docs-align.sh --offline  # without GitHub
```

Read every `FAIL` and `WARN`. The `info` lines under "statements about the
README" are for judgement: open each and ask whether it is still true of the
current README. A comment that quotes a README sentence is stale the moment
that sentence is rewritten.

On macOS the script runs `make docs` inside the `kelyfos-dev` Lima VM when it
is running; `make docs` is Linux-only.

## 2. What to update, by trigger

**A release was tagged.**
- `CHANGELOG.md` gets its section first; `tools/changelog.py --check` refuses a
  tag without one. The newest `## vX.Y.Z — YYYY-MM-DD` heading is where
  `make docs` reads the release that `llms.txt` and `llms-full.txt` name, so
  run `make docs` after the section exists and commit the two files.
- `docs/upgrading.md`: any section headed with a date `(YYYY-MM-DD)` because it
  landed on `main` before a tag gets the release name instead, `(vX.Y.Z)`.
  Never renumber sections; other documents cite the numbers.
- `docs/compatibility.md` §7 lists what is post-1.0. Remove what shipped.
- README performance numbers come from `bench.yml` (boot, restore; ten runs)
  and `caps.yml` (five-agent team; one run). Both are manual:
  `gh workflow run bench.yml` and `gh workflow run caps.yml`, then copy the
  figures from the run summary into the README's Performance table and the
  changelog's timing line. Local numbers are never published (nested
  virtualisation is 6–8× slower).

**A document was added under `docs/`.**
- A row in both tables of `docs/README.md` ("Start here" and "The map") and an
  entry in its inventory (`### name.md — …` with *Concept* / *Reference* /
  *Thin*).
- An entry in `docSet()` in `tools/gendocs/llms.go`, or a named omission in
  `TestEveryDocumentUnderDocsIsInTheLLMsSet`. Then `make docs`.

**A cookbook recipe was added or changed.**
- Every recipe starts in its own temporary directory:
  `work="$(mktemp -d)"; cd "$work"; trap 'rm -rf "$work"' EXIT`. The cookbook
  workflow runs recipes as root inside a checkout owned by another uid, and a
  bare `kelyfos run` from the checkout is refused by the policy-ownership
  check.
- The count in the cookbook's first sentence is checked by its extractor; the
  same word appears twice in `docs/README.md` and in its inventory heading.
- Run the one recipe in Lima the way the workflow does:
  `sudo -E env "PATH=$PWD/bin:$PATH" "HOME=$HOME" bash dev/cookbook.sh <name>`.

**The README changed.**
- Keep the `## Quickstart` and `## Security` headings: `docs/cookbook.md`
  links the first anchor and `docs/security-assertions.md` names the second's
  table.
- `llms-full.txt` embeds the README; `make docs` and commit.
- Files that describe the README (the checker lists them): `SECURITY.md`,
  `docs/hardening.md` "Replaced at P5-4", `CONTRIBUTING.md`,
  `tools/sbom/coverage_test.go`, `.github/workflows/repro-check.yml`,
  `dev/audit-supply-chain.sh`, `dev/fetch-image.sh`, `tools/gendocs/llms.go`.

**The CLI's output changed.**
- Re-record the demo in Lima: `bash dev/demo-record.sh --record` writes
  `docs/media/demo.cast` and `demo.gif`. Check the four beats are in the cast:
  a `ready in`, a refusal with its `add allow` fix line, `team up in`, and
  `chain intact`.

## 3. Verify and commit

- `bash dev/docs-align.sh` reports no failures.
- `make ci-act` green before pushing to `main` (CLAUDE.md). A docs-only
  change still runs the `checks` job, which includes the reference drift gate.
- Commit with a DCO sign-off (`git commit -s`), message in the repository's
  style: a `scope: what` subject, a body that says why.
