#!/usr/bin/env python3
"""Patch the SnuSnuRoot prebuilt carriers for a different kernel build.

The hwbinder NULL-write targets selinux_enforcing, whose VA differs per
firmware build. Upstream ships PS7331 (0xffffff8009971668). This tool
rewrites the address in both carriers for the target build:

  1. libhwbinder_target.so (arm64) - the address is materialized in code
     as a MOVN/MOVK sequence at a unique site (found by scanning for the
     known PS7331 constant). Rewritten as MOVZ/MOVK/MOVK.
  2. snusnu_hwbinder_root (arm64) - the address is a single 8-byte
     literal in the RX segment. Rewritten in place.

The arm32 .so is NOT patched: the stateful primitive is rejected on the
32-bit Binder compat ABI before any kernel address is used (upstream
design), so it carries no address.

Usage:
    python patch-address.py --from 0xffffff8009971668 --to 0xffffff8009965628 \
        --so <libhwbinder_target.so> --carrier <snusnu_hwbinder_root> --out <dir>

Verifies: exactly one site per binary, old value matches, new value
written, and (for the .so) the reconstructed instruction sequence decodes
to the new address.
"""

import argparse
import shutil
import struct
import sys
from pathlib import Path


def movk_mask(hw):
    return 0xFFFF << (hw * 16)


def find_movn_movk_site(d: bytes, addr: int, window: int = 8):
    """Find the (unique) MOVN/MOVZ + MOVK.. sequence building `addr`."""
    sites = []
    for i in range(0, len(d) - 4 * window, 4):
        w = struct.unpack('<I', d[i:i + 4])[0]
        val = None
        rd = w & 0x1F
        if (w & 0xFFE00000) == 0x92800000 and ((w >> 21) & 3) == 0:
            val = (~((w >> 5) & 0xFFFF)) & 0xFFFFFFFFFFFFFFFF
        elif (w & 0xFFE00000) == 0xD2800000 and ((w >> 21) & 3) == 0:
            val = (w >> 5) & 0xFFFF
        else:
            continue
        for j in range(1, window):
            w2 = struct.unpack('<I', d[i + j * 4:i + j * 4 + 4])[0]
            if (w2 & 0xFF800000) == 0xF2800000:
                hw2 = (w2 >> 21) & 3
                imm2 = (w2 >> 5) & 0xFFFF
                rd2 = w2 & 0x1F
                if rd2 == rd:
                    val = (val & ~movk_mask(hw2)) | (imm2 << (hw2 * 16))
        if val == addr:
            sites.append(i)
    return sites


def encode_movz(rd: int, imm16: int) -> int:
    return 0xD2800000 | (imm16 << 5) | rd


def encode_movn(rd: int, imm16: int) -> int:
    return 0x92800000 | (imm16 << 5) | rd


def encode_movk(rd: int, imm16: int, hw: int) -> int:
    return 0xF2800000 | (hw << 21) | (imm16 << 5) | rd


def build_sequence(addr: int, rd: int):
    """Return (list of (word, shift) for nonzero 16-bit lanes, initial word).

    The original sequence starts with MOVN (all-ones base) because the PS7331
    address has 0xffff in lane 3. MOVN x, #~lane0 produces 0xffff..lane0, 
    upper lanes all ones, which is correct whenever lane 3 is 0xffff (the
    subsequent MOVKs overwrite lanes 1-2 as needed). This keeps the original
    instruction shape (same slots, same register).
    """
    lanes = [(addr >> (16 * k)) & 0xFFFF for k in range(4)]
    words = []
    if lanes[3] == 0xFFFF:
        words.append(('movn', encode_movn(rd, (~lanes[0]) & 0xFFFF)))
    else:
        words.append(('movz', encode_movz(rd, lanes[0])))
        for k in (1, 2, 3):
            if lanes[k]:
                words.append(('movk', encode_movk(rd, lanes[k], k)))
    return words


def patch_so(data: bytes, old: int, new: int) -> bytes:
    sites = find_movn_movk_site(data, old)
    if len(sites) != 1:
        sys.exit(f'libhwbinder_target.so: expected exactly 1 site for '
                 f'0x{old:x}, found {len(sites)}')
    off = sites[0]
    d = bytearray(data)
    # decode the original sequence to learn the register and layout
    w0 = struct.unpack('<I', d[off:off + 4])[0]
    rd = w0 & 0x1F
    # find the movk instructions in the following window (same rd)
    movk_slots = []  # (offset, hw)
    for j in range(1, 8):
        o = off + j * 4
        w = struct.unpack('<I', d[o:o + 4])[0]
        if (w & 0xFF800000) == 0xF2800000 and (w & 0x1F) == rd:
            movk_slots.append((o, (w >> 21) & 3))
    new_lanes = [(new >> (16 * k)) & 0xFFFF for k in range(4)]
    old_lanes = [(old >> (16 * k)) & 0xFFFF for k in range(4)]
    # lane 0: rewrite the initial movn/movz.
    # MOVN base (upper lanes all ones) is valid whenever lane3 == 0xffff;
    # the movk slots overwrite lanes 1-2 as needed. This preserves the
    # original instruction shape (same slots, same register).
    if new_lanes[3] == 0xFFFF:
        d[off:off + 4] = struct.pack('<I', encode_movn(rd, (~new_lanes[0]) & 0xFFFF))
    else:
        d[off:off + 4] = struct.pack('<I', encode_movz(rd, new_lanes[0]))
        have_lane3 = any(hw == 3 for (_, hw) in movk_slots)
        if new_lanes[3] and not have_lane3:
            sys.exit('cannot patch: new address needs a lane-3 MOVK but the '
                     'original sequence has no slot for it')
    # lanes 1..3: rewrite existing movk slots where the lane changed
    for (o, hw) in movk_slots:
        if new_lanes[hw] != old_lanes[hw]:
            d[o:o + 4] = struct.pack('<I', encode_movk(rd, new_lanes[hw], hw))
    # verify
    patched = bytes(d)
    check = find_movn_movk_site(patched, new)
    if len(check) != 1 or check[0] != off:
        sys.exit(f'patch verification failed: rebuilt sequence does not '
                 f'decode to 0x{new:x} at 0x{off:x}')
    return patched


def patch_carrier(data: bytes, old: int, new: int) -> bytes:
    old_b = struct.pack('<Q', old)
    new_b = struct.pack('<Q', new)
    count = data.count(old_b)
    if count != 1:
        sys.exit(f'snusnu_hwbinder_root: expected exactly 1 literal for '
                 f'0x{old:x}, found {count}')
    d = bytearray(data)
    i = d.find(old_b)
    d[i:i + 8] = new_b
    patched = bytes(d)
    if patched.count(new_b) != 1 or patched.count(old_b) != 0:
        sys.exit('carrier patch verification failed')
    return patched


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--from', dest='old', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--to', dest='new', required=True, type=lambda x: int(x, 0))
    ap.add_argument('--so', type=Path, required=True)
    ap.add_argument('--carrier', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    so_data = args.so.read_bytes()
    so_patched = patch_so(so_data, args.old, args.new)
    so_out = args.out / args.so.name
    so_out.write_bytes(so_patched)
    print(f'patched {so_out.name}: 0x{args.old:x} -> 0x{args.new:x} '
          f'(movn/movk site rewritten, verified)')

    car_data = args.carrier.read_bytes()
    car_patched = patch_carrier(car_data, args.old, args.new)
    car_out = args.out / args.carrier.name
    car_out.write_bytes(car_patched)
    print(f'patched {car_out.name}: 0x{args.old:x} -> 0x{args.new:x} '
          f'(literal rewritten, verified)')


if __name__ == '__main__':
    main()
