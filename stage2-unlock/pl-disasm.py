#!/usr/bin/env python3
"""Preloader/LK disassembly helper for the trona (MT8183) boot chain.

Resolves the ARM32 Thumb-2 PC-relative string idiom used by both bootloaders:

    ldr  rX, [pc, #imm]     ; literal D at address A (word-aligned pool)
    add  rX, pc             ; at address B; rX = D + B + 4

so string_VA = D + B + 4, and file offset = string_VA - LOAD_BASE.

Usage:
    python pl-disasm.py str <file> <start> <end>     # resolve string refs in range
    python pl-disasm.py dis <file> <start> <end>     # disassemble range
    python pl-disasm.py find <file> <hexstring>      # locate a byte pattern
"""
import sys
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

# Preloader: EMMC_BOOT header (0x200) + GFH (0x800) + payload; payload is
# linked at 0x483df000 (derived from the _LK_VER: literal at file 0x109ec).
PL_BASE = 0x483DF000
# LK: 0x200 container header + payload linked at 0x56000000.
LK_BASE = 0x56000000

BASES = {"preloader": PL_BASE, "lk": LK_BASE}


def load(path):
    with open(path, "rb") as fh:
        return fh.read()


def base_for(path):
    name = path.lower()
    if "lk" in name and "preloader" not in name:
        return LK_BASE
    return PL_BASE


def cstr(data, off, limit=96):
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("latin1")


def _string_ref(data, insns, i, base):
    """Resolve `ldr rX,[pc,#imm]` ... `add rX, pc` to a string file offset."""
    a = insns[i]
    if a.mnemonic != "ldr" or "[pc," not in a.op_str:
        return None
    try:
        reg = a.op_str.split(",")[0].strip()
        imm = int(a.op_str.split("#")[1].rstrip("]"), 0)
    except (ValueError, IndexError):
        return None
    lit = ((a.address + 4) & ~3) + imm
    if lit + 4 > len(data):
        return None
    d = struct.unpack_from("<I", data, lit)[0]
    for j in range(i + 1, min(i + 8, len(insns))):
        b = insns[j]
        if b.mnemonic == "add" and b.op_str == "%s, pc" % reg:
            # The literal holds a *displacement*, not an address: the target is
            # `literal + add_addr + 4`.  Note the `add` is not necessarily the
            # instruction right after the `ldr` -- compilers interleave other
            # instructions (preloader 0x252c0 has a `movs` in between), so the
            # search window above has to cover a few instructions.
            #
            # Do not shorten this to `literal` alone: the displacement happens to
            # look like a plausible file offset often enough to be mistaken for
            # one, which is what an earlier comment here claimed.
            off = (d + b.address + 4) & 0xFFFFFFFF
            if not (0 <= off < len(data) - 4):
                off = off - base
            if 0 <= off < len(data) - 4:
                chunk = data[off:off + 8]
                if chunk and all(32 <= c < 127 for c in chunk):
                    return off
            return None
    return None


def resolve_strings(data, start, end, base):
    """Yield (addr, file_off, string) for ldr/add string refs."""
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    insns = list(md.disasm(data[start:end], start))
    out = []
    for i in range(len(insns)):
        off = _string_ref(data, insns, i, base)
        if off is not None:
            out.append((insns[i].address, off, cstr(data, off)))
    return out


def disasm(data, start, end, base):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False
    insns = list(md.disasm(data[start:end], start))
    for i, ins in enumerate(insns):
        note = ""
        off = _string_ref(data, insns, i, base)
        if off is not None:
            note = "   ; -> %06x %r" % (off, cstr(data, off, 64))
        elif ins.mnemonic == "ldr" and "[pc," in ins.op_str:
            try:
                imm = int(ins.op_str.split("#")[1].rstrip("]"), 0)
                lit = ((ins.address + 4) & ~3) + imm
                if lit + 4 <= len(data):
                    note = "   ; lit=%08x" % struct.unpack_from("<I", data, lit)[0]
            except (ValueError, IndexError):
                pass
        print("%06x  %-10s %-32s%s" % (ins.address, ins.mnemonic, ins.op_str, note))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    cmd, path = sys.argv[1], sys.argv[2]
    data = load(path)
    base = base_for(path)
    if cmd == "str":
        start, end = int(sys.argv[3], 0), int(sys.argv[4], 0)
        for a, off, s in resolve_strings(data, start, end, base):
            print("%06x -> %06x  %r" % (a, off, s))
    elif cmd == "dis":
        start, end = int(sys.argv[3], 0), int(sys.argv[4], 0)
        disasm(data, start, end, base)
    elif cmd == "find":
        pat = bytes.fromhex(sys.argv[3])
        i = data.find(pat)
        while i >= 0:
            print("file %06x  va %08x" % (i, i + base))
            i = data.find(pat, i + 1)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
