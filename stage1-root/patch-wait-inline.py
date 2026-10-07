#!/usr/bin/env python3
"""Rescale the INLINE nanosleep timespec in the statically linked arm64 carrier.

`patch-wait.py` handles libhwbinder_target.so, where the compiler kept the
{tv_sec, tv_nsec} pair in one shared .rodata literal. The statically linked
`snusnu_hwbinder_root` -- built from the same controlled_target.c, and the binary
the stage-4 boot actor actually executes -- materialises the same 1 ms wait
inline instead:

    mov  x7, #0x4240          ; movz  imm16 = 0x4240
    movk x7, #0xf, lsl #16    ; movk  imm16 = 0xf  -> x7 = 0xF4240 = 1000000 ns
    stp  xzr, x7, [sp, #N]    ; the timespec
    mov  x8, #0x65            ; __NR_nanosleep
    svc  #0

So there is no single data byte to rewrite; the constant is two instruction
immediates. This rewrites every such pair, which is the exact analogue of the
proven libhwbinder_target.so 1 ms -> 10 ms fix documented in
docs/ENODATA-ANALYSIS.md (the stage-0x50 race needs a ~4 s window, not ~0.4 s).

The pairing is what makes this safe: a lone `movz #0x4240` could be anything,
but the 32-bit word immediately followed by its matching `movk ...,lsl #16` of
0xf is unambiguous -- that combination is how a 20-bit constant 0xF4240 is
built, and 0xF4240 is 1 ms in nanoseconds.

Usage:
    python patch-wait-inline.py --bin <snusnu_hwbinder_root> \
        [--from-ns 1000000] [--to-ns 10000000] [--dry-run]
"""
import argparse
import hashlib
import struct
import sys
from pathlib import Path


def movz_x(imm16: int, rd: int) -> int:
    return 0xD2800000 | (imm16 << 5) | rd


def movk_x_lsl16(imm16: int, rd: int) -> int:
    return 0xF2800000 | (0x1 << 21) | (imm16 << 5) | rd


def find_sites(data: bytes, nsec: int):
    """All movz/movk halves building exactly `nsec`, per register.

    The two halves are NOT always adjacent: the compiler reorders around them,
    so pairing by `movz Rd` -> nearest following `movk Rd, lsl #16` is required.
    A pair is trustworthy because 0xF4240 (1 ms in ns) is an otherwise arbitrary
    20-bit constant, and in this binary the counts match exactly (9 movz, 9 movk,
    one movk per movz, same register).
    """
    lo, hi = nsec & 0xFFFF, (nsec >> 16) & 0xFFFF
    movz, movk = [], []
    for off in range(0, len(data) - 3, 4):
        word = struct.unpack_from("<I", data, off)[0]
        for rd in range(32):
            if word == movz_x(lo, rd):
                movz.append((off, rd))
            elif word == movk_x_lsl16(hi, rd):
                movk.append((off, rd))

    pairs, used = [], set()
    for off, rd in movz:
        candidates = [(mo, mr) for mo, mr in movk if mr == rd and mo > off and mo not in used]
        if not candidates:
            return None, f"movz @0x{off:x} (x{rd}) has no following movk of the same register"
        near, _ = min(candidates)
        used.add(near)
        pairs.append((off, near, rd))
    if len(used) != len(movk):
        return None, f"{len(movk) - len(used)} movk site(s) left unpaired"
    return pairs, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", type=Path, required=True, help="arm64 carrier to patch in place")
    ap.add_argument("--from-ns", type=int, default=1_000_000)
    ap.add_argument("--to-ns", type=int, default=10_000_000)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify", action="store_true",
                    help="assert the file carries --to-ns and not --from-ns, then exit")
    args = ap.parse_args()

    if args.verify:
        data = args.bin.read_bytes()
        have, err = find_sites(data, args.to_ns)
        stale, _ = find_sites(data, args.from_ns)
        if err or not have:
            sys.exit(f"{args.bin.name}: NOT patched ({err or 'no ' + str(args.to_ns) + ' ns site'})")
        if stale:
            sys.exit(f"{args.bin.name}: mixed - {len(stale)} stale {args.from_ns} ns site(s) remain")
        print(f"{args.bin.name}: OK - {len(have)} site(s) at {args.to_ns} ns, none at {args.from_ns} ns")
        return 0

    if not (0 < args.to_ns < 1_000_000_000):
        sys.exit(f"tv_nsec out of range: {args.to_ns}")
    if args.to_ns == args.from_ns:
        sys.exit("from-ns and to-ns are identical")

    data = args.bin.read_bytes()
    old_sha = hashlib.sha256(data).hexdigest()

    to_pairs, err = find_sites(data, args.to_ns)
    if to_pairs:
        sys.exit(f"already carries {args.to_ns} ns at {[hex(m) for m, _, _ in to_pairs]}")
    old_pairs, err = find_sites(data, args.from_ns)
    if err:
        sys.exit(f"cannot pair the {args.from_ns} ns constant: {err}")
    if not old_pairs:
        sys.exit(f"no {'{'}movz #{hex(args.from_ns & 0xffff)}, movk #{hex(args.from_ns >> 16)}, "
                 f"lsl #16{'}'} pair found")

    lo, hi = args.to_ns & 0xFFFF, (args.to_ns >> 16) & 0xFFFF
    patched = bytearray(data)
    for movz_off, movk_off, rd in old_pairs:
        struct.pack_into("<I", patched, movz_off, movz_x(lo, rd))
        struct.pack_into("<I", patched, movk_off, movk_x_lsl16(hi, rd))
    patched = bytes(patched)

    # Same verification discipline as patch-wait.py: prove the change did exactly
    # what was intended and nothing else.
    if len(patched) != len(data):
        sys.exit("verification failed: size changed")
    leftover, err = find_sites(patched, args.from_ns)
    if leftover:
        sys.exit("verification failed: old constant still present")
    new_pairs, err = find_sites(patched, args.to_ns)
    if err or len(new_pairs) != len(old_pairs):
        sys.exit(f"verification failed: new constant count {len(new_pairs)} "
                 f"!= old count {len(old_pairs)} ({err})")
    diff = [i for i, (a, b) in enumerate(zip(data, patched)) if a != b]
    # 2 immediate bytes changed per half, and only the high bytes move because
    # 0x4240 -> 0x9680 and 0xf -> 0x98 each keep the low byte's low nibble out of
    # the encoding, so 4 bytes per pair is exact.
    allowed = {(off + k) for off in (m for p in old_pairs for m in p[:2]) for k in range(4)}
    if any(i not in allowed for i in diff):
        sys.exit(f"verification failed: bytes outside the immediate fields differ: {diff[:8]}")

    print(f"{args.bin.name}: {len(old_pairs)} inline timespec site(s), "
          f"register(s) {sorted({rd for _, _, rd in old_pairs})}")
    for movz_off, movk_off, rd in old_pairs:
        print(f"  x{rd}: movz@0x{movz_off:x} movk@0x{movk_off:x}  "
              f"{args.from_ns} -> {args.to_ns} ns ({args.from_ns/1e6:.0f} -> {args.to_ns/1e6:.0f} ms)")
    print(f"  bytes changed: {len(diff)} (expected {4 * len(old_pairs)})")
    print(f"  sha256: {old_sha}")
    print(f"      ->  {hashlib.sha256(patched).hexdigest()}")

    if args.dry_run:
        print("  dry run: not written")
        return 0
    args.bin.write_bytes(patched)
    print("  written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
