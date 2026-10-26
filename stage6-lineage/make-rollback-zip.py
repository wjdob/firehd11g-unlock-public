#!/usr/bin/env python3
"""Build a rollback package that restores only system, vendor and boot.

Why this exists: a stock Fire OS OTA also writes the preloader, both TEE slots and
the LK. On an unlocked device that is the one write with no recovery path. This
tool rewrites a stock OTA so its updater script touches only the three partitions
the LineageOS build replaces, and leaves every other byte of the package alone.

Usage:
    python stage6-lineage/make-rollback-zip.py --stock OTA.bin --out rollback.zip
    python stage6-lineage/make-rollback-zip.py --stock OTA.bin --dry-run

--dry-run prints the generated script and writes nothing else, which is how the
edify is reviewed before a 1.2 GB repack.

The result is unsigned. TWRP's zip signature verification must be off, and that
trade is deliberate: a package that cannot reach the preloader is worth more than
a valid signature.
"""
from __future__ import annotations

import argparse
import shutil
import sys
import zipfile

SCRIPT = "META-INF/com/google/android/updater-script"
DROP_IF = (
    "less_than_int",      # aborts when the installed build is newer than the package
    "images/",            # preloader, lk, tee1/tee2, spmfw, sspm, cam_vpu1-3
    "target.blocklist",   # Amazon recovery metadata
)


def trim(text: str) -> str:
    kept = []
    for line in text.splitlines():
        if any(marker in line for marker in DROP_IF):
            continue
        kept.append(line.rstrip())
    while kept and not kept[-1].strip():
        kept.pop()
    return "\n".join(kept) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stock", required=True, help="stock Fire OS OTA (.bin or .zip)")
    ap.add_argument("--out", help="output zip path (required unless --dry-run)")
    ap.add_argument("--dry-run", action="store_true", help="print the script, write nothing")
    args = ap.parse_args()

    with zipfile.ZipFile(args.stock) as zf:
        try:
            original = zf.read(SCRIPT).decode("utf-8", "replace")
        except KeyError:
            print("no %s in %s" % (SCRIPT, args.stock))
            return 2

    new = trim(original)
    if "--dry-run" in sys.argv or args.dry_run:
        print(new)
        return 0
    if not args.out:
        print("--out is required unless --dry-run is given")
        return 2

    with zipfile.ZipFile(args.stock) as zin, zipfile.ZipFile(args.out, "w") as zout:
        for item in zin.infolist():
            info = zipfile.ZipInfo(item.filename, date_time=item.date_time)
            info.compress_type = item.compress_type
            info.external_attr = item.external_attr
            info.create_system = item.create_system
            if item.filename == SCRIPT:
                zout.writestr(info, new.encode())
                continue
            with zin.open(item) as src, zout.open(info, "w") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)

    print("wrote %s" % args.out)
    print("entries: %d" % (len(zipfile.ZipFile(args.out).infolist())))
    print("reminder: unsigned package, so disable TWRP zip signature verification")
    return 0


if __name__ == "__main__":
    sys.exit(main())
