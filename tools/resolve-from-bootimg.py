#!/usr/bin/env python3
"""Resolve selinux_enforcing from a boot.img (running-device dump).

Same pipeline as extract-symbols.py but starting from a boot image instead
of an OTA zip, so the address can be resolved from the ACTUAL running
kernel rather than a matching OTA build.

Usage:
    python resolve-from-bootimg.py <boot.img> <out-dir>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import importlib.util

spec = importlib.util.spec_from_file_location(
    'extract_symbols', Path(__file__).resolve().parent / 'extract-symbols.py')
es = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    bootimg = Path(sys.argv[1])
    out_dir = Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    kernel = es.bootimg_to_raw_kernel(bootimg, out_dir)
    elf = es.raw_to_elf(kernel, out_dir, 'vmlinux-to-elf')
    elf_bytes = elf.read_bytes()
    sections = es.load_sections(elf_bytes)
    syms = es.load_symbols(elf_bytes, sections)

    print(f'== {bootimg.name} ==')
    print(f'symbols: {len(syms)}')
    for name in ['commit_creds', 'avc_denied', 'selinux_capable',
                 'enforcing_setup']:
        if name in syms:
            print(f'  {name:20s} 0x{syms[name]:016x}')

    print('\nselinux_enforcing candidates:')
    ranked = es.find_selinux_enforcing(elf_bytes, sections, syms)
    for entry in ranked[:5]:
        count, addr, refs = entry[0], entry[1], entry[2]
        method = entry[3] if len(entry) > 3 else '?'
        locs = ', '.join(f'0x{p:x}({k})' for p, k in refs[:8])
        print(f'  0x{addr:016x}  refs={count}  method={method}  [{locs}]')

    if ranked:
        best = ranked[0]
        method = best[3] if len(best) > 3 else '?'
        print(f'\nBest candidate: selinux_enforcing = 0x{best[1]:016x} '
              f'({best[0]} references, via {method})')
        print('Cross-check: PS7319/1726=0xffffff8009965628, '
              'PS7326=0xffffff8009969668, PS7331=0xffffff8009971668.')


if __name__ == '__main__':
    main()