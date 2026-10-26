#!/usr/bin/env python3
"""Writing-style pass: remove em dashes from prose without changing meaning.

Usage:
    python tools/style-pass.py --dry-run [paths...]   # show what would change
    python tools/style-pass.py --apply   [paths...]   # rewrite in place

Rules, applied in order, to prose only (fenced code blocks and inline code spans
are left untouched):

  1. headings                    "Title - Subtitle"     -> "Title: Subtitle"
  2. bold labels                 "**Label** - text"     -> "**Label**: text"
  3. paired dashes in prose      "a - aside - b"        -> "a (aside) b"
  4. table cells, any dash       "a - b"                -> "a; b"
  5. dash before a conjunction   "fails - but only if"  -> "fails, but only if"
  6. dash before a new clause    "fails - the loop..."  -> "fails; the loop..."
  7. everything else             "gate - it runs..."    -> "gate, it runs..."

Rule order matters: the paired-dash rule must run before the single-dash rules, and
table rows must never take the paired rule, because a row's pipe separators look
like sentence boundaries and a parenthesis would swallow the cell layout.

En dashes are deliberately NOT touched: they carry numeric and identifier ranges
(S1-S4, 10-40 min), where they are correct and unambiguous.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

EM = "\u2014"
ROOT = Path(__file__).resolve().parents[1]

# Text-like files that carry prose. Binaries and licence texts are excluded: the
# latter must stay verbatim, and .bin/.img are device images.
PATTERNS = ("*.md", "*.MD", "*.txt", "*.tsv", "*.py", "*.ps1", "*.sh", "*.json",
            "*.inf", "*.cdf")

# A dash joining two independent clauses needs a semicolon; a dash introducing a
# coordinating conjunction needs only a comma.
NEW_CLAUSE = ("this ", "that ", "these ", "those ", "it ", "they ", "he ", "she ",
              "we ", "you ", "there ", "the ", "a ", "an ")
CONJUNCTIONS = ("and ", "but ", "so ", "then ", "yet ", "or ", "nor ")


def is_table_row(stripped: str) -> bool:
    body = stripped.lstrip("> ").lstrip()
    return body.startswith("|")


def fix_prose(segment: str, in_table: bool) -> str:
    if EM not in segment:
        return segment

    # 2. bold label followed by a dash becomes a colon, unless the dash is
    #    simply joining a conjunction ("**Yes** - and this is...").
    def bold_label(m: re.Match) -> str:
        tail = segment[m.end():].lstrip().lower()
        return m.group(1) + (", " if tail.startswith(CONJUNCTIONS) else ": ")
    segment = re.sub(r"(\*\*)\s*" + EM + r"\s+", bold_label, segment)
    if EM not in segment:
        return segment

    # 3. exactly two dashes in prose become parentheses.
    if not in_table and segment.count(EM) == 2:
        first = segment.find(EM)
        second = segment.find(EM, first + 1)
        aside = segment[first + 1:second].strip()
        if aside and not aside.endswith((".", "!", "?", ";")):
            return "%s(%s)%s" % (segment[:first].rstrip(), aside, segment[second + 1:])

    # 4-7. remaining single dashes.
    out = []
    rest = segment
    while EM in rest:
        i = rest.find(EM)
        head, tail = rest[:i], rest[i + 1:].lstrip()
        low = tail.lower()
        if low.startswith(CONJUNCTIONS):
            joiner = ", " if not in_table else ", "
        elif in_table:
            joiner = "; "
        elif low.startswith(CONJUNCTIONS):
            joiner = ", "
        elif low.startswith(NEW_CLAUSE):
            joiner = "; "
        else:
            joiner = ", "
        out.append(head.rstrip())
        out.append(joiner)
        rest = tail
    out.append(rest)
    return "".join(out)


def fix_line(line: str) -> str:
    stripped = line.lstrip()
    prefix = line[:len(line) - len(stripped)]
    m = re.match(r"(#{1,6}\s+)(.*)$", stripped)
    if m and EM in m.group(2):
        body = re.sub(r"\s*" + EM + r"\s*", ": ", m.group(2))
        return prefix + m.group(1) + body.replace(": : ", ": ")
    in_table = is_table_row(stripped)
    parts = stripped.split("`")
    for idx in range(0, len(parts), 2):
        parts[idx] = fix_prose(parts[idx], in_table)
    result = prefix + "`".join(parts)
    # A dash sitting between two separate code spans lands in an odd (protected)
    # segment. If one survives, it is prose, so fix the whole line.
    if EM in result:
        result = prefix + fix_prose(stripped, in_table)
    return result


def process(path: Path, apply: bool, include_code: bool = False) -> int:
    text = path.read_text(encoding="utf-8")
    if EM not in text:
        return 0
    lines = text.split("\n")
    changed = 0
    fence = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence and not include_code:
            continue
        new = fix_line(line)
        if new != line:
            lines[i] = new
            changed += 1
    if apply and changed:
        path.write_text("\n".join(lines), encoding="utf-8", newline="")
    return changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dry-run", action="store_true")
    g.add_argument("--apply", action="store_true")
    ap.add_argument("--include-code", action="store_true",
                    help="also rewrite fenced code blocks and diagrams")
    args = ap.parse_args()

    targets = []
    if args.paths:
        for p in args.paths:
            if Path(p).is_dir():
                for pattern in PATTERNS:
                    targets.extend(sorted(Path(p).rglob(pattern)))
            else:
                targets.append(Path(p))
    else:
        skip = {".git", "refs", "OTAs", "ota-extract", "stage2a-unlock",
                "__pycache__", "mediatekTools", "licenses", ".tmp-style"}
        for pattern in PATTERNS:
            for p in sorted(ROOT.rglob(pattern)):
                if not any(part in skip for part in p.parts):
                    targets.append(p)
        # Extension-less documents that ship and are prose.
        for name in ("NOTICE", "LICENSE"):
            p = ROOT / name
            if p.exists():
                targets.append(p)

    total = 0
    for path in targets:
        n = process(path, args.apply, args.include_code)
        if n:
            rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
            print("%-56s %4d line(s)" % (rel, n))
            total += n
    print("%s: %d line(s) across %d file(s)" % ("applied" if args.apply else "would change",
                                                total, len(targets)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
