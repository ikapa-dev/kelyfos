#!/usr/bin/env python3
"""Cut one release's notes out of CHANGELOG.md (P6-16, D50).

CHANGELOG.md is the source the release notes are cut from, not a mirror of them.
That only means something if a release cannot be published without its section,
so this exits non-zero when a tag has none — which fails the release workflow at
the step before `gh release create`, rather than publishing a release whose notes
say nothing and then asking somebody to remember to fix it.

Usage:  tools/changelog.py v0.9        # print that section's body
        tools/changelog.py --check     # every published tag has a section
"""
import re
import subprocess
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"

# A section is `## v0.9 — 2026-08-24`, or `## Unreleased — v1.0` for the one
# being written. The tag has to be matched on a word boundary so that `v0.1`
# does not match `v0.10` the day that exists.
SECTION = re.compile(r"^## (.+)$", re.MULTILINE)


def sections(text):
    """Every `## ` heading with the body under it, in file order."""
    out = []
    marks = list(SECTION.finditer(text))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append((m.group(1).strip(), text[m.end():end].strip()))
    return out


# A release candidate carries the notes of the version it is a candidate FOR.
#
# `v1.0-rc1` is not a separate release with separate news; it is v1.0, offered
# early so the numbers in the README can be measured against the artifacts that
# will ship. Giving it its own CHANGELOG section would put a second copy of
# v1.0's notes in the file, and a second copy of the truth that nothing keeps
# honest is the failure D50 exists to prevent. So the suffix is stripped and the
# base version's section is used, and the workflow says out loud that it did
# that rather than doing it silently.
RC = re.compile(r"-(rc|alpha|beta|pre)\.?\d*$", re.IGNORECASE)


def find(text, tag):
    if find_exact(text, tag) == (None, None):
        base = RC.sub("", tag)
        if base != tag:
            heading, body = find_exact(text, base)
            if heading is not None:
                print(f"# notes for {tag} taken from {base}'s section: a candidate "
                      f"carries the notes of the release it is a candidate for",
                      file=sys.stderr)
                return heading, body
    return find_exact(text, tag)


def find_exact(text, tag):
    for heading, body in sections(text):
        # `## v0.9 — the headline` and `## v0.9 — 2026-08-24` both match v0.9;
        # `## Unreleased — v1.0` matches v1.0, so the section being written is
        # publishable the moment it is tagged without being renamed first.
        if re.search(rf"(?<![\w.]){re.escape(tag)}(?![\w.])", heading):
            return heading, body
    return None, None


def published_tags():
    out = subprocess.run(["git", "tag"], capture_output=True, text=True, check=True)
    return [t for t in out.stdout.split() if re.fullmatch(r"v\d+\.\d+", t)]


def main():
    text = CHANGELOG.read_text()

    if "--check" in sys.argv:
        missing = [t for t in published_tags() if find(text, t)[0] is None]
        if missing:
            print(
                f"CHANGELOG.md has no section for: {', '.join(sorted(missing))}\n"
                "Every published tag needs one — the release workflow cuts its notes "
                "from this file, so a tag with no section is a release with no notes.",
                file=sys.stderr,
            )
            return 1
        print(f"CHANGELOG.md covers all {len(published_tags())} published tags")
        return 0

    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    tag = sys.argv[1]
    heading, body = find(text, tag)
    if heading is None:
        print(
            f"CHANGELOG.md has no section for {tag}.\n"
            f"    Add one — `## {tag} — <date>` with a headline under it — and tag again.\n"
            "    The notes are cut from that file rather than typed into a web form, so a\n"
            "    release without one would publish notes nothing in this repository can check.",
            file=sys.stderr,
        )
        return 1
    if not body:
        print(f"CHANGELOG.md's section for {tag} is empty.", file=sys.stderr)
        return 1
    print(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
