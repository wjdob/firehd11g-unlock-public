#!/usr/bin/env python3
"""Parse an Amazon IDME database dump (magic 'beefdeed2.1').

The IDME lives in eMMC boot partition 1 (mmcblk0boot1). Entry format:
  name[16] (NUL-padded) + len[4] + count[4] + type[4] + value[len], 4-byte aligned.

Usage:
  python idme-parse.py <mmcblk0boot1.bin> [--json] [--field NAME]
"""
import argparse
import json
import struct
import sys

MAGIC = b"beefdeed2.1"


def parse(data: bytes) -> list[dict]:
    if not data.startswith(MAGIC):
        raise SystemExit(f"not an IDME dump (magic {data[:16]!r})")
    entries = []
    off = 0x10
    while off + 28 <= len(data):
        raw_name = data[off : off + 16]
        name = raw_name.split(b"\x00")[0]
        if not name or not all(32 <= c < 127 for c in name):
            break
        vlen, count, vtype = struct.unpack_from("<III", data, off + 16)
        if vlen > len(data) - (off + 28):
            break
        value = data[off + 28 : off + 28 + vlen]
        entries.append(
            {
                "offset": off,
                "name": name.decode("ascii"),
                "len": vlen,
                "count": count,
                "type": vtype,
                "value": value,
            }
        )
        off += 28 + vlen
        off = (off + 3) & ~3
    return entries


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--field", help="print one field's value (hex)")
    args = ap.parse_args()

    data = open(args.dump, "rb").read()
    entries = parse(data)

    if args.field:
        for e in entries:
            if e["name"] == args.field:
                print(e["value"].hex())
                return
        raise SystemExit(f"field not found: {args.field}")

    if args.json:
        out = [
            {
                "offset": e["offset"],
                "name": e["name"],
                "len": e["len"],
                "value": e["value"].split(b"\x00")[0].decode("ascii", "replace"),
                "value_hex": e["value"].hex(),
            }
            for e in entries
        ]
        json.dump(out, sys.stdout, indent=2)
        return

    print(f"{len(entries)} entries")
    for e in entries:
        v = e["value"].split(b"\x00")[0].decode("ascii", "ignore")
        print(f"  @0x{e['offset']:04x} {e['name']:<16} len={e['len']:<5d} val={v[:50]!r}")


if __name__ == "__main__":
    main()
