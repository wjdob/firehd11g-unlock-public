#!/usr/bin/env python3
"""Sync the stage2a-unlock/ handoff bundle from the repo and rebuild MANIFEST.txt.

`stage2a-unlock/` is the snapshot that gets zipped and sent to external reviewers.
This tool is the single source of truth for *what* the bundle contains and keeps it
in step with the repo, so the drift fixed up by hand in earlier sessions cannot
recur.

    python tools/sync-handoff-bundle.py            # sync + rewrite MANIFEST.txt
    python tools/sync-handoff-bundle.py --check     # report what would change, change nothing

Then, to export:

    python tools/check-bundle-drift.py
    python stage2a-unlock/verify-manifest.py
    & 'C:\\Program Files\\7-Zip\\7z.exe' a -tzip -mx=9 stage2a-unlock<date>.zip stage2a-unlock

`README.md` at the top of the bundle is *not* copied from the repo -- it is a
separate reviewer-facing introduction -- so this tool never writes it.
"""
from __future__ import annotations

import argparse
import filecmp
import fnmatch
import hashlib
import os
import shutil
import sys
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(REPO, "stage2a-unlock")

# What belongs in the bundle, as globs relative to the repo root.
# Keep the bundle lean: it exists to be reviewed, not to mirror everything.
SPECS = [
    "diagnostics/dram-map-1735.txt",
    "diagnostics/dt-reserved.txt",
    "diagnostics/iomem.txt",
    "diagnostics/fastboot-gate-probe.txt",
    "diagnostics/fastboot-getvar-all.txt",
    "docs/brick-analysis.md",
    "docs/HANDOFF.md",
    "docs/references.md",
    "docs/RESUME-HERE.md",
    "docs/root-method.md",
    # Deliberately explicit: dumps/ holds many more partitions than the bundle
    # carries. These seven are the curated set (GPT copies, both boot areas, and
    # the three small early partitions). Do not widen this to dumps/trona-1735/* --
    # the remaining dumps are large and may contain unique device data.
    #
    # mmcblk0boot1.bin is deliberately ABSENT. It is the IDME database, and it
    # contains this unit's serial, WiFi MAC, Bluetooth MAC and PSN/FSN. The bundle
    # is the artefact that gets zipped and shared, so shipping a raw IDME image
    # would publish hardware identifiers. The IDME *analysis* is unaffected: the
    # findings are written up in stage2-unlock/README.md and tools/idme-parse.py
    # lets a reader parse a dump of their own device. Verified 2026-10-06 that
    # boot0, p4, p5, p6 and p7 carry no MAC-like or serial data.
    "dumps/trona-1735/gpt-backup.bin",
    "dumps/trona-1735/gpt-primary.bin",
    "dumps/trona-1735/mmcblk0boot0.bin",
    "dumps/trona-1735/mmcblk0p4.bin",
    "dumps/trona-1735/mmcblk0p5.bin",
    "dumps/trona-1735/mmcblk0p6.bin",
    "dumps/trona-1735/mmcblk0p7.bin",
    "ota-extract/images/*",
    "stage2-unlock/*",
    "stage3-recovery/README.md",
    "stage3-recovery/host/winusb-fastboot/*",
    "tools/idme-parse.py",
    # Added session 2: the cross-referencer that produced the "Open questions
    # closed" findings. The repo-maintenance tools (bundle sync/drift) stay out --
    # they mean nothing to an external reviewer.
    "tools/pl-xref.py",
    # Exploit-surface audit against the public MTK bootloader projects
    # (amonet-koboreru, kaeru), the reusable preloader classifier, and the
    # 2026-10 MT8183 research hub: the continuity anchor, the rated exploit
    # register and the boot-chain map (exploits/*.md), the evidence under
    # exploits/notes/ and the analysis tooling under exploits/tools/.
    # "**" is recursive -- see wanted(). Do not narrow this back to "exploits/*":
    # that silently drops notes/ and tools/ from the review bundle.
    "exploits/**",
    # Stage 4: persistent-root mechanism, installer, and the on-device evidence for
    # how far the unattended chain gets. "app/**" is recursive (see wanted()) and
    # carries the three source changes the README points a reviewer at; the built
    # APK is excluded so a binary cannot drift from the source beside it.
    "stage4-persistent/*",
    "stage4-persistent/app/**",
    # The authoritative write-up for the ENODATA race and both of its corrections.
    # Four documents already shipped in this bundle reference it, and the stage-4
    # retry finding lives only here -- without it a reviewer cannot follow the
    # reliability argument.
    "docs/ENODATA-ANALYSIS.md",
]

# Never copied into the bundle even if a spec above would match them.
# *.apk / *.idsig keep build output out: apksigner also writes an .idsig v4
# signature sidecar, which is build output just as much as the APK is.
EXCLUDE = ["__pycache__", "*.pyc", "*.upstream.bak", "*.apk", "*.idsig"]

# Files that live *only* in the bundle and are never copied from the repo. They
# still have to appear in MANIFEST.txt, otherwise verify-manifest.py reports them
# as UNLISTED.
BUNDLE_LOCAL = ["README.md"]


def wanted() -> list[str]:
    """Repo-relative paths that the bundle should contain.

    A spec is "<dir>/<glob>" and matches files directly in <dir>. A spec ending
    in "/**" matches recursively, which is needed for trees like
    stage4-persistent/app/ whose interesting files are in nested directories.
    """
    out: set[str] = set()
    for spec in SPECS:
        if spec.endswith("/**"):
            root = os.path.join(REPO, spec[:-3])
            if not os.path.isdir(root):
                print("  ! recursive spec has no directory, skipping: %s" % spec)
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames
                               if not any(fnmatch.fnmatch(d, ex) for ex in EXCLUDE)]
                for name in filenames:
                    if any(fnmatch.fnmatch(name, ex) for ex in EXCLUDE):
                        continue
                    full = os.path.join(dirpath, name)
                    out.add(os.path.relpath(full, REPO).replace(os.sep, "/"))
            continue

        directory = os.path.dirname(spec)
        pattern = os.path.basename(spec)
        root = os.path.join(REPO, directory) if directory else REPO
        if not os.path.isdir(root):
            print("  ! spec has no directory, skipping: %s" % spec)
            continue
        for name in os.listdir(root):
            full = os.path.join(root, name)
            if not os.path.isfile(full):
                continue
            if not fnmatch.fnmatch(name, pattern):
                continue
            rel = os.path.join(directory, name).replace(os.sep, "/")
            if any(fnmatch.fnmatch(name, ex) for ex in EXCLUDE):
                continue
            out.add(rel)
    return sorted(out)


def sha256(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def write_manifest(files: list[str]) -> None:
    rows = []
    for rel in files:
        path = os.path.join(BUNDLE, rel.replace("/", os.sep))
        rows.append((rel, os.path.getsize(path), sha256(path)))

    total = sum(r[1] for r in rows) / (1 << 20)
    lines = [
        "stage2a-unlock - file manifest",
        "=" * 78,
        "Generated: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        # Deliberately not the absolute repo path: this file ships inside the
        # bundle, and a machine path leaks the builder's username.
        "Source   : repository working tree (uncommitted research)",
        "Files    : %d   Total: %.1f MB" % (len(rows), total),
        "",
        "Verify from inside stage2a-unlock/:   python verify-manifest.py",
        "",
        "%-56s %12s  %s" % ("path", "bytes", "sha256"),
        "%-56s %12s  %s" % ("-" * 56, "-" * 12, "-" * 64),
    ]
    for rel, size, digest in rows:
        lines.append("%-56s %12d  %s" % (rel, size, digest))

    # verify-manifest.py skips lines beginning with these words, so a path that
    # happened to start with one of them would silently disappear from the check.
    for rel, _, _ in rows:
        head = rel.split("/", 1)[0]
        if head in ("stage2a-unlock", "path"):
            raise SystemExit("bundle path starts with a skipped word: %s" % rel)

    with open(os.path.join(BUNDLE, "MANIFEST.txt"), "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="report differences without changing anything")
    args = ap.parse_args()

    files = wanted()
    copied = orphaned = identical = 0

    if not args.check:
        os.makedirs(BUNDLE, exist_ok=True)

    for rel in files:
        src = os.path.join(REPO, rel.replace("/", os.sep))
        dst = os.path.join(BUNDLE, rel.replace("/", os.sep))
        if os.path.exists(dst) and filecmp.cmp(src, dst, shallow=False):
            identical += 1
            continue
        action = "same" if os.path.exists(dst) else "NEW "
        print("  %s %s" % (action, rel))
        copied += 1
        if not args.check:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)

    # Anything in the bundle that is no longer wanted.
    keep = set(files) | set(BUNDLE_LOCAL) | {"MANIFEST.txt", "verify-manifest.py"}
    for dirpath, dirnames, filenames in os.walk(BUNDLE):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), BUNDLE).replace(os.sep, "/")
            if rel not in keep:
                print("  STALE (not in SPECS) %s" % rel)
                orphaned += 1
                if not args.check:
                    os.remove(os.path.join(dirpath, fn))

    if args.check:
        print("%d file(s) would be synced, %d identical, %d stale" %
              (copied, identical, orphaned))
        return 1 if copied or orphaned else 0

    # The manifest must cover every file in the bundle, including the ones that
    # only exist here, or verify-manifest.py reports them as UNLISTED.
    manifest_files = sorted(
        set(files) | {rel for rel in BUNDLE_LOCAL if os.path.exists(os.path.join(BUNDLE, rel))}
    )
    write_manifest(manifest_files)
    print("%d synced, %d already identical, %d stale removed, %d files in manifest" %
          (copied, identical, orphaned, len(manifest_files)))
    print("MANIFEST.txt rewritten. Now run:")
    print("    python stage2a-unlock/verify-manifest.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())

