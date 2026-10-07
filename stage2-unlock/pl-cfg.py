#!/usr/bin/env python3
"""Preloader control-flow helper for the trona (MTK8183) boot chain.

Complements pl-disasm.py (string resolution) with branch / code-pointer
analysis, so questions like "is this function on the boot path?" can be
answered offline.

Usage:
    python pl-cfg.py build   <image> [cache.json]
    python pl-cfg.py callers <cache.json> <addr>          # direct branch sources
    python pl-cfg.py ptr     <cache.json> <value>         # literal loads yielding value
    python pl-cfg.py cref    <cache.json> <addr>          # `ldr+add pc` refs to addr
    python pl-cfg.py reach   <cache.json> <addr> [addr...]# ancestors of addr(s)
    python pl-cfg.py funcs   <cache.json> <addr>          # disassemble at addr

`build` decodes the whole image (Thumb-2) and records:
  * edges   : every direct branch/cbz/cbnz/table-branch source -> target
  * lits    : every pc-relative load source -> (literal file offset, value)
  * crefs   : every resolved `ldr rX,[pc,#imm]; add rX, pc` -> resolving source
  * entries : heuristically detected function entry points

`cref` is the one that matters for code pointers: these images build function
addresses in registers, so a raw u32 scan finds nothing (this is how the
preloader hands the 0x291a5 restore stub to an external component).

Note: the preloader's link base is NOT established, so all addresses are file
offsets. Absolute pointers that appear as literals are reported verbatim.
"""
import json
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BRANCH_MNEMONICS = {
    "b", "b.w", "bl", "bl.w", "blx", "bx", "cbz", "cbnz", "beq", "bne",
    "bhs", "blo", "bhi", "bls", "bge", "blt", "bgt", "ble", "bmi", "bpl",
    "bcs", "bcc", "bvs", "bvc", "bal",
}


def _target(op_str):
    """Parse a '#<hex>' operand into an int, or None."""
    s = op_str.strip()
    if not s.startswith("#"):
        return None
    try:
        return int(s[1:], 16)
    except ValueError:
        return None


def _pcrel(op_str):
    """Return the literal file offset for 'rX, [pc, #imm]' or None."""
    if "[pc," not in op_str:
        return None
    try:
        imm = int(op_str.split("#")[1].rstrip("]"), 0)
        src = _pcrel.addr
        return ((src + 4) & ~3) + imm
    except (ValueError, IndexError):
        return None


def build(path, cache):
    d = open(path, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = False
    md.skipdata = True
    insns = list(md.disasm(d, 0))
    edges, lits, crefs = {}, {}, {}
    for i, ins in enumerate(insns):
        m = ins.mnemonic
        # data (skipdata) shows up as '.byte' with no operands
        if m in BRANCH_MNEMONICS or m.startswith(("b.", "bl.", "cb")):
            if ins.op_str.startswith("#"):
                t = _target(ins.op_str)
                if t is not None:
                    edges.setdefault(str(ins.address), []).append(t)
        if m in ("ldr", "ldr.w") and "[pc," in ins.op_str:
            try:
                reg = ins.op_str.split(",")[0].strip()
                imm = int(ins.op_str.split("#")[1].rstrip("]"), 0)
            except (ValueError, IndexError):
                continue
            lit = ((ins.address + 4) & ~3) + imm
            if lit + 4 > len(d):
                continue
            val = struct.unpack_from("<I", d, lit)[0]
            lits[str(ins.address)] = [lit, val]
            for j in range(i + 1, min(i + 5, len(insns))):
                b = insns[j]
                if b.mnemonic == "add" and b.op_str == "%s, pc" % reg:
                    crefs.setdefault(str((val + b.address + 4) & 0xFFFFFFFF),
                                     []).append(ins.address)
                    break

    # function entries: direct branch targets
    entries = sorted({t for v in edges.values() for t in v if 0 <= t < len(d)})

    blob = {"image": path, "size": len(d), "edges": edges, "lits": lits,
            "crefs": crefs, "entries": entries}
    with open(cache, "w") as fh:
        json.dump(blob, fh)
    print("built %s: %d branch sources, %d pc-relative loads, %d computed refs"
          % (cache, len(edges), len(lits), len(crefs)))


def _load(cache):
    with open(cache) as fh:
        return json.load(fh)


def _num(s):
    return int(s, 0)


def cmd_callers(blob, addr):
    out = sorted(int(s) for s, ts in blob["edges"].items() if addr in ts)
    print("direct branch sources -> 0x%x (%d):" % (addr, len(out)))
    for a in out:
        print("   0x%06x" % a)
    # also report any pc-relative load whose *value* points here (Thumb bit set)
    for s, (lit, val) in sorted(blob["lits"].items(), key=lambda kv: int(kv[0])):
        if val in (addr, addr | 1):
            print("   via literal: 0x%06x -> [0x%x] = 0x%08x" % (int(s), lit, val))


def cmd_ptr(blob, value):
    print("pc-relative loads yielding 0x%x:" % value)
    found = False
    for s, (lit, val) in sorted(blob["lits"].items(), key=lambda kv: int(kv[0])):
        if val == value:
            print("   0x%06x  literal@0x%x" % (int(s), lit))
            found = True
    if not found:
        print("   none")


def cmd_cref(blob, addr):
    """`ldr rX,[pc,#imm]; add rX, pc` sites that resolve to addr (or addr|1)."""
    print("computed (`ldr+add pc`) references to 0x%x:" % addr)
    found = False
    for resolved, srcs in sorted(blob.get("crefs", {}).items(), key=lambda kv: int(kv[0])):
        r = int(resolved)
        if r in (addr, addr | 1, addr & ~1):
            for src in srcs:
                print("   0x%06x -> 0x%06x%s" % (src, r, "  (Thumb)" if r & 1 else ""))
            found = True
    if not found:
        print("   none")


def cmd_reach(blob, starts, limit=200000):
    """Report which of `starts` are reachable from known roots; also list the
    ancestor chain for the first reachable start."""
    roots = [0x19A22]            # main boot flow (see README function map)
    rev = {}
    for s, ts in blob["edges"].items():
        for t in ts:
            rev.setdefault(t, set()).add(int(s))
    # BFS backwards from each start to the roots
    for start in starts:
        seen, queue, found = set(), [start], None
        while queue:
            cur = queue.pop()
            if cur in seen:
                continue
            seen.add(cur)
            if cur in roots:
                found = cur
                break
            for p in rev.get(cur, ()):
                if p not in seen:
                    queue.append(p)
        print("0x%06x: %s (%d ancestors explored)"
              % (start, "reachable from main 0x%x" % found if found
                 else "NOT reachable backwards from 0x%x" % roots[0], len(seen)))


def cmd_funcs(blob, addr):
    d = open(blob["image"], "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.skipdata = True
    insns = list(md.disasm(d[addr:addr + 0x400], addr))
    for ins in insns[:80]:
        print("%06x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "build":
        build(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "pl-cfg.json")
        return 0
    blob = _load(sys.argv[2])
    if cmd == "callers":
        cmd_callers(blob, _num(sys.argv[3]))
    elif cmd == "ptr":
        cmd_ptr(blob, _num(sys.argv[3]))
    elif cmd == "cref":
        cmd_cref(blob, _num(sys.argv[3]))
    elif cmd == "reach":
        cmd_reach(blob, [_num(a) for a in sys.argv[3:]])
    elif cmd == "funcs":
        cmd_funcs(blob, _num(sys.argv[3]))
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
