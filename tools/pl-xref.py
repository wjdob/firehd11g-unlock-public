#!/usr/bin/env python3
"""Cross-reference string references in the trona preloader / LK images.

Why this exists
---------------
`pl-disasm.py` resolves the preloader's PC-relative string idiom with capstone,
but it must be *started on a valid instruction boundary*.  Started anywhere else
(0x800, say) capstone desynchronises and the whole range decodes to garbage,
silently yielding zero references -- which is exactly the trap that made the
string table look unreachable.

This tool is alignment-independent: it scans the raw bytes for the halfword
encodings themselves, so it works anywhere in the image.

The idiom
---------
    ldr  rX, [pc, #imm]      ; literal D, file offset of a *displacement*
    ...                      ; the `add` is NOT always adjacent
    add  rX, pc              ; string_file_offset = D + add_addr + 4

The literal holds a displacement, not an address, so the resolved value is only
correct when the `add` instruction's own address is used.  Verified against
preloader 0x252c0, which resolves to 0x35af7 -- the "[RTC]RTC 32K mode setting
wrong. Enter first boot/recovery." string -- matching the address recorded in
stage2-unlock/README.md.

Usage
-----
    python tools/pl-xref.py <image> [--grep TEXT] [--range LO HI]

Images are not committed (`*.img` is in .gitignore); point at your local copy,
e.g. ota-extract/images/preloader.img.
"""
from __future__ import annotations

import argparse
import struct
import sys

# Payload link base and file offset, per pl-disasm.py.  The file->VA bias is
# derived in stage2-unlock/README.md from the literal at file 0x109ec.
PL_FILE = 0xA00
PL_VA = 0x483DF000
LK_FILE = 0x200
LK_VA = 0x56000000


def bias_for(path: str) -> tuple[int, int]:
    """Return (file_offset_of_payload, va_of_payload)."""
    name = path.lower().replace("\\", "/")
    if "lk" in name and "preloader" not in name:
        return LK_FILE, LK_VA
    return PL_FILE, PL_VA


def is_printable_ascii(data: bytes, off: int, n: int = 8) -> bool:
    if not (0 <= off < len(data) - n):
        return False
    return all(32 <= c < 127 for c in data[off:off + n])


def cstr(data: bytes, off: int, limit: int = 96) -> str:
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("latin1")


def is_add_pc(hw: int, reg: int) -> bool:
    """Thumb `add rX, pc` == 0x4478 | Rd, low registers only (D bit clear)."""
    return (hw & 0xFF78) == 0x4478 and (hw & 0x80) == 0 and (hw & 0x7) == reg


def scan(data: bytes, window: int = 10):
    """Yield (ldr_addr, add_addr, literal_addr, disp, target_off).

    Handles both encodings of the literal load:

      T1  `ldr rX, [pc, #imm8*4]`  -- halfword 0x48xx, immediate is in WORDS
      T2  `ldr.w rX, [pc, #imm12]` -- halfwords 0xF8DF, imm12; immediate in BYTES

    Getting the T1 scale wrong is silent: the literal read lands 4x too close to
    the instruction, the displacement is garbage, and every reference is missed.
    """
    n = len(data)
    for i in range(0, n - 4, 2):
        h1 = data[i] | (data[i + 1] << 8)
        reg = lit = None
        if (h1 & 0xF800) == 0x4800:                     # T1
            reg = (h1 >> 8) & 0x7
            lit = ((i + 4) & ~3) + ((h1 & 0xFF) << 2)
        elif (h1 & 0xFF7F) == 0xF85F:                   # T2 (ldr.w, U=1, Rn=pc)
            if i + 4 > n:
                continue
            h2 = data[i + 2] | (data[i + 3] << 8)
            if (h2 & 0xF000) != 0xF000:                 # must be an imm12 form
                continue
            reg = (h2 >> 12) & 0xF
            lit = ((i + 4) & ~3) + (h2 & 0xFFF)
        if reg is None or lit is None or lit + 4 > n:
            continue
        disp = struct.unpack_from("<I", data, lit)[0]

        # Look ahead for the matching `add rX, pc`.  It is usually within a few
        # instructions but is not necessarily adjacent.
        for k in range(1, window):
            j = i + 2 * k
            if j + 2 > n:
                break
            h3 = data[j] | (data[j + 1] << 8)
            if is_add_pc(h3, reg & 0x7) and (reg < 8 or (h3 & 0x80) != 0):
                yield i, j, lit, disp, (disp + j + 4) & 0xFFFFFFFF
                break


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image")
    ap.add_argument("--grep", help="only show references whose string contains TEXT (case-insensitive)")
    ap.add_argument("--range", nargs=2, type=lambda s: int(s, 0), metavar=("LO", "HI"),
                    help="only show references from this code address range")
    ap.add_argument("--all", action="store_true", help="also show non-printable targets")
    args = ap.parse_args()

    with open(args.image, "rb") as fh:
        data = fh.read()
    payload_file, payload_va = bias_for(args.image)
    bias = payload_va - payload_file
    print("image %s  size 0x%x  file->va bias 0x%08x" % (args.image, len(data), bias))

    hits = []
    for ldr, add, lit, disp, target in scan(data):
        printable = is_printable_ascii(data, target)
        if not printable and not args.all:
            continue
        if args.range and not (args.range[0] <= ldr <= args.range[1]):
            continue
        text = cstr(data, target) if printable else ""
        if args.grep and args.grep.lower() not in text.lower():
            continue
        hits.append((ldr, add, lit, disp, target, text))

    for ldr, add, lit, disp, target, text in hits:
        print("  code %06x  add@%06x  lit@%06x disp %08x  ->  str %06x  %r"
              % (ldr, add, lit, disp, target, text))
    print("%d reference(s)" % len(hits))
    return 0


if __name__ == "__main__":
    sys.exit(main())
