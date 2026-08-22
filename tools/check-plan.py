#!/usr/bin/env python3
"""Check PLAN.html is still coherent.

PLAN.html is the source of truth and the live status tracker, so a broken one is
a real defect rather than a cosmetic one: a duplicated task id, a decision left
"pending" after the gate it belongs to, or a dangling anchor all mean the
document is lying about the project. This is the audit that ran by hand
throughout Phase 0-3, made permanent.
"""
import html.parser
import re
import sys
import pathlib

PLAN = pathlib.Path(__file__).resolve().parent.parent / "PLAN.html"


class Balanced(html.parser.HTMLParser):
    VOID = {"br", "hr", "img", "input", "meta", "link"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.errors = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}>")
            return
        if self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1]}>")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
        else:
            self.stack.pop()


def main() -> int:
    s = PLAN.read_text()
    problems = []

    parser = Balanced()
    parser.feed(s)
    problems += parser.errors
    if parser.stack:
        problems.append(f"unclosed tags at end of file: {parser.stack}")

    ids = re.findall(r'<span class="tid">([^<]+)</span>', s)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        problems.append(f"duplicate task ids: {dupes}")

    boxes = len(re.findall(r'type="checkbox"', s))
    if boxes != len(ids):
        problems.append(f"{boxes} checkboxes but {len(ids)} task ids")

    # Every task id mentioned anywhere must exist, so a log entry cannot cite a
    # task that was renamed or never written.
    referenced = set(re.findall(r"\b(P[0-4]-\d+)\b", s))
    missing = sorted(referenced - set(ids))
    if missing:
        problems.append(f"referenced but undefined task ids: {missing}")

    anchors = set(re.findall(r'\bid="([^"]+)"', s))
    broken = sorted(set(re.findall(r'href="#([^"]+)"', s)) - anchors)
    if broken:
        problems.append(f"broken anchors: {broken}")

    for field in ("focus", "meta-status", "meta-updated"):
        if not re.search(rf'id="{field}"[^>]*>[^<]', s):
            problems.append(f'#{field} is missing or empty')

    # A phase marked done with unchecked tasks would misreport progress.
    for m in re.finditer(r'<section class="phase" id="p(\d)"[^>]*data-status="([^"]+)"', s):
        seg = s[m.start(): s.index("</section>", m.start())]
        total = seg.count('type="checkbox"')
        checked = seg.count('<input checked type="checkbox"')
        if m.group(2) == "done" and checked != total:
            problems.append(f"phase {m.group(1)} is marked done with {checked}/{total} tasks checked")

    if problems:
        print("PLAN.html is not coherent:")
        for p in problems:
            print("  -", p)
        return 1

    checked = len(re.findall(r'<input checked type="checkbox"', s))
    print(f"PLAN.html is coherent: {len(ids)} tasks, {checked} checked, "
          f"{len(re.findall(r'<td class=.mono.>D[0-9]+</td>', s))} decisions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
