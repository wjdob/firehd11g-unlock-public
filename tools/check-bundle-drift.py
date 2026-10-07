#!/usr/bin/env python3
"""Check that the stage2a-unlock/ handoff bundle has not drifted from the repo.

`stage2a-unlock/` is a distribution snapshot: every file in it is a copy of a file
in the repository (plus a bundle-specific README.md). Copies rot, and this repo has
already been bitten once -- `stage2a-unlock10062026.zip` was exported and then went
stale because the bundle was not re-synced after later edits.

Run this after touching any file that the bundle mirrors:

    python tools/check-bundle-drift.py

Exit status 0 == the bundle is an exact copy of the repo sources.

Note that the bundle's *binaries* (dumps/, ota-extract/*.img, *.bin) are deliberately
excluded from git by .gitignore, but they are still present in the working tree, so
they are compared here too.

The bundle's own README.md is not a copy of the repo's root README.md -- it is a
separate reviewer-facing introduction -- so it is listed as an intentional exception.
"""
from __future__ import annotations

import hashlib
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(REPO, "stage2a-unlock")

# Files that live in the bundle but are generated from, or maintained
# independently of, the repo tree.
GENERATED = {"MANIFEST.txt", "verify-manifest.py"}
INTENTIONAL = {
    # The bundle's own introduction for external reviewers; the repo root README.md
    # is a different document.
    "README.md",
}


def sha256(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def main() -> int:
    if not os.path.isdir(BUNDLE):
        print("stage2a-unlock/ not found -- nothing to check.")
        return 0

    same = differ = missing = skipped = 0
    problems: list[str] = []

    for dirpath, dirnames, filenames in os.walk(BUNDLE):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, BUNDLE).replace(os.sep, "/")

            if rel in GENERATED:
                skipped += 1
                continue
            if rel in INTENTIONAL:
                skipped += 1
                continue

            src = os.path.join(REPO, rel.replace("/", os.sep))
            if not os.path.exists(src):
                missing += 1
                problems.append("NO SOURCE  %s   (in the bundle but not in the repo)" % rel)
                continue

            if sha256(path) == sha256(src):
                same += 1
            else:
                differ += 1
                problems.append("DRIFTED    %s" % rel)

    print("%d in sync, %d drifted, %d without a repo source, %d skipped"
          % (same, differ, missing, skipped))
    for p in problems:
        print("  " + p)

    if differ or missing:
        print()
        print("Re-sync the bundle before exporting, then regenerate MANIFEST.txt:")
        print("    copy the changed files into stage2a-unlock/")
        print("    python tools/check-bundle-drift.py")
        print("    python stage2a-unlock/verify-manifest.py   (after regenerating the manifest)")
        return 1

    print("RESULT: PASS - the handoff bundle matches the repo sources")
    return 0


if __name__ == "__main__":
    sys.exit(main())
