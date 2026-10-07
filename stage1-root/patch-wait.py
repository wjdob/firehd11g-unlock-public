#!/usr/bin/env python3
"""Rescale the shared nanosleep timespec literal in the arm64 JNI carrier.

Every wait_one_millisecond() call site in libhwbinder_target.so consumes ONE
shared 16-byte literal {tv_sec=0, tv_nsec=<ns>} (verified in
docs/ENODATA-ANALYSIS.md: file offset 0x11c0, the only occurrence, 15 load
sites, 36 nanosleep call sites). Rewriting tv_nsec rescales every wait in
the carrier at once:

  - the stage-0x50 post-close wait (RCU grace-period margin for the freed
    epitem before the replace workers spray)
  - the worker release spacing and tail (the spray window)
  - the setup-phase post-close waits (retained_epitem_alloc, spray_epitems)
  - the EAGAIN/ready poll loops (early-exit; worst case only)

The kernel has CONFIG_HIGH_RES_TIMERS=y, so these nanosleeps are genuine
hrtimer sleeps and the rescale has real effect (not jiffy-quantized).

Default 1 ms -> 10 ms widens the stage-0x50 race window from ~0.4 s to
~4 s, covering the RCU grace-period tail that causes ENODATA misses
(~43% of fresh boots observed pre-patch). Companion change required:
reroot_after_boot.sh leak/write `nc -w` must be >= 20 (carrier answers
in ~4-5 s after the patch).

Usage:
    python patch-wait.py --so <libhwbinder_target.so> \
        [--from-ns 1000000] [--to-ns 10000000]

Verifies: exactly one {0, from_ns} literal before; exactly one {0, to_ns}
and zero {0, from_ns} after; prints old/new sha256. Patches in place
(git history is the backup).
"""

import argparse
import hashlib
import struct
import sys
from pathlib import Path


def find_literal(data: bytes, tv_sec: int, tv_nsec: int):
    return data.find(struct.pack('<qq', tv_sec, tv_nsec))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--so', type=Path, required=True,
                    help='libhwbinder_target.so (arm64) to patch in place')
    ap.add_argument('--from-ns', type=int, default=1000000,
                    help='current tv_nsec (default 1000000 = 1 ms)')
    ap.add_argument('--to-ns', type=int, default=10000000,
                    help='new tv_nsec (default 10000000 = 10 ms)')
    args = ap.parse_args()

    if not (0 < args.to_ns < 1000000000):
        sys.exit(f'tv_nsec out of range: {args.to_ns}')
    if args.to_ns == args.from_ns:
        sys.exit('from-ns and to-ns are identical')

    data = args.so.read_bytes()
    old_sha = hashlib.sha256(data).hexdigest()

    off = find_literal(data, 0, args.from_ns)
    if off < 0:
        sys.exit(f'no {{{0}, {args.from_ns}}} literal found - already patched '
                 f'or wrong file?')
    if find_literal(data, 0, args.from_ns, ) != off:
        pass  # find returns first; count below is the real check
    if data.count(struct.pack('<qq', 0, args.from_ns)) != 1:
        sys.exit('expected exactly one shared timespec literal, found '
                 f'{data.count(struct.pack("<qq", 0, args.from_ns))}')

    patched = bytearray(data)
    struct.pack_into('<q', patched, off + 8, args.to_ns)
    patched = bytes(patched)

    if patched.count(struct.pack('<qq', 0, args.to_ns)) != 1:
        sys.exit('patch verification failed: new literal count != 1')
    if patched.count(struct.pack('<qq', 0, args.from_ns)) != 0:
        sys.exit('patch verification failed: old literal still present')
    if len(patched) != len(data):
        sys.exit('patch verification failed: size changed')
    diff = [i for i, (a, b) in enumerate(zip(data, patched)) if a != b]
    if not all(off + 8 <= i < off + 16 for i in diff):
        sys.exit(f'patch verification failed: bytes outside tv_nsec differ: {diff}')
    if len(diff) > 8:
        sys.exit(f'patch verification failed: {len(diff)} bytes differ (expected <= 8)')

    new_sha = hashlib.sha256(patched).hexdigest()
    args.so.write_bytes(patched)
    print(f'patched {args.so.name} in place:')
    print(f'  tv_nsec @ file offset 0x{off + 8:x}: '
          f'{args.from_ns} -> {args.to_ns} ({args.from_ns/1e6:.0f} ms -> '
          f'{args.to_ns/1e6:.0f} ms)')
    print(f'  sha256: {old_sha}')
    print(f'      ->  {new_sha}')


if __name__ == '__main__':
    main()
