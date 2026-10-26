#!/usr/bin/env python3
"""Build a root-chain carrier variant for a firmware version.

The hwbinder NULL-write targets `selinux_enforcing`, whose VA differs per
firmware build (see tools/kernel-symbols.md). The live chain stages exactly
one carrier binary - stage1-root/carriers/<key>/libhwbinder_target.so -
selected by the device's PS build token (stage1-root/carriers/carriers.tsv,
the single source of truth also read by stage0/run-diagnostics.ps1).

This tool produces a new variant from the live-proven base
(carriers/ps7319 - the run-18 wait-patched build) by rewriting the
embedded address:

  1. Resolve the target address, either directly (--addr) or by running
     the validated extraction pipeline on an OTA image (--ota).
  2. Patch the MOVN/MOVK code site (reuses stage1-root/patch-address.py).
  3. Verify: exactly one site for the new address, zero for the old, the
     10 ms wait literal intact (docs/ENODATA-ANALYSIS.md).
  4. Write the variant + print sha256 and registration instructions.

Usage:
    python make-carrier.py --ota <update-kindle-*.bin>          # extract + build
    python make-carrier.py --addr 0xffffff80099xxxxxx --label <key>

Registering a new version (after building):
    add a row to stage1-root/carriers/carriers.tsv:
        <PS-token>\t<key>\t<addr>\t<sha256>
    then re-run stage0/run-diagnostics.ps1 (the version gate reads the tsv).

Requires (only for --ota): pip install vmlinux-to-elf peewee lz4 click capstone
"""

import argparse
import hashlib
import importlib.util
import re
import struct
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BASE_CARRIER = HERE / 'carriers' / 'ps7319' / 'libhwbinder_target.so'
BASE_ADDR = 0xFFFFFF8009965628          # PS7319 (the base carrier's constant)
TSV = HERE / 'carriers' / 'carriers.tsv'
WAIT_LITERAL = struct.pack('<qq', 0, 10_000_000)   # the 10 ms ENODATA patch


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read_tsv():
    """Return {ps_token: (key, addr, sha256, verified)} from carriers.tsv.

    The registry has a 5th column (comma-separated live-verified
    ro.build.version.incremental values). It is optional and may be empty, so
    accept 4 or 5 fields: requiring exactly 4 silently emptied the whole table
    the moment the column was added, and a registry that parses to {} reads as
    "no known firmware" rather than "this script is out of date".
    """
    table = {}
    if not TSV.exists():
        return table
    for line in TSV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) == 4:
            parts.append('')
        if len(parts) != 5:
            continue
        token, key, addr, sha, verified = parts
        table[token] = (key, int(addr, 0), sha, verified)
    return table


def variant_is_current(key: str, sha: str) -> bool:
    """True if carriers/<key>/libhwbinder_target.so exists and hashes to sha."""
    if not sha or set(sha) <= set('<fill>'):
        return False
    f = HERE / 'carriers' / key / 'libhwbinder_target.so'
    if not f.exists():
        return False
    import hashlib
    return hashlib.sha256(f.read_bytes()).hexdigest() == sha


def ps_token_from_ota(ota: Path) -> str:
    with zipfile.ZipFile(ota) as z:
        bp = z.read('system/build.prop').decode(errors='replace')
    m = re.search(r'ro\.build\.id=(PS\d+)', bp)
    if not m:
        sys.exit(f'could not parse a PS build token from {ota.name} '
                 f'(ro.build.id missing/unrecognized)')
    return m.group(1)


def extract_addr(ota: Path, workdir: Path):
    es = load_module('extract_symbols', REPO / 'tools' / 'extract-symbols.py')
    workdir.mkdir(parents=True, exist_ok=True)
    bootimg = es.ota_to_bootimg(ota, workdir)
    kernel = es.bootimg_to_raw_kernel(bootimg, workdir)
    elf = es.raw_to_elf(kernel, workdir, 'vmlinux-to-elf')
    elf_bytes = elf.read_bytes()
    sections = es.load_sections(elf_bytes)
    syms = es.load_symbols(elf_bytes, sections)
    ranked = es.find_selinux_enforcing(elf_bytes, sections, syms)
    if not ranked:
        sys.exit('extraction found no selinux_enforcing candidate - '
                 'do NOT guess; report the OTA')
    count, addr, refs, method = ranked[0]
    print(f'extracted selinux_enforcing = 0x{addr:016x} '
          f'({count} refs, method={method})')
    if method != 'enforcing_setup':
        sys.exit('candidate came from the HEURISTIC fallback, not the '
                 'definitive enforcing_setup anchor - refusing to build a '
                 'carrier from it (override manually only after review)')
    return addr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ota', type=Path, help='Amazon OTA .bin (extract addr)')
    ap.add_argument('--addr', type=lambda x: int(x, 0),
                    help='target selinux_enforcing VA directly')
    ap.add_argument('--label', help='variant key (dir name under carriers/)')
    ap.add_argument('--out', type=Path,
                    help='output dir (default carriers/<label>)')
    ap.add_argument('--force', action='store_true',
                    help='overwrite an existing variant that differs')
    args = ap.parse_args()

    if not BASE_CARRIER.exists():
        sys.exit(f'base carrier missing: {BASE_CARRIER}')
    base = BASE_CARRIER.read_bytes()
    if base.count(WAIT_LITERAL) != 1:
        sys.exit('base carrier does not carry the 10 ms wait literal - '
                 'refusing to build from an unpatched base '
                 '(see docs/ENODATA-ANALYSIS.md)')

    table = read_tsv()

    if args.ota:
        token = ps_token_from_ota(args.ota)
        print(f'OTA build token: {token}')
        if token in table:
            key, addr, sha, _verified = table[token]
            if variant_is_current(key, sha):
                print(f'{token} is a KNOWN version: variant "{key}" '
                      f'(selinux_enforcing 0x{addr:016x}) already exists - '
                      f'nothing to do.')
                return
            print(f'{token} registered as "{key}" but the carrier is '
                  f'missing/stale - building it.')
            label = key
        else:
            addr = extract_addr(args.ota, REPO / 'ota-extract' / f'{token.lower()}')
            label = args.label or token.lower()
            for kt, (k, a, s, _v) in table.items():
                if a == addr:
                    if variant_is_current(k, s):
                        print(f'extracted address matches existing variant '
                              f'"{k}" (registered for {kt}). To support '
                              f'{token}, register it against that variant in '
                              f'carriers.tsv:')
                        print(f'    {token}\t{k}\t0x{addr:016x}\t{s}')
                        return
                    print(f'extracted address matches variant "{k}" '
                          f'(missing/stale) - building it.')
                    label = k
                    break
    elif args.addr:
        addr = args.addr
        label = None
        for kt, (k, a, s, _v) in table.items():
            if a == addr:
                if variant_is_current(k, s):
                    print(f'address matches existing variant "{k}" '
                          f'(registered for {kt}) - nothing to do.')
                    return
                print(f'address matches variant "{k}" (missing/stale) - '
                      f'building it.')
                label = k
                break
        if label is None:
            if not args.label:
                sys.exit('--label is required with --addr for an unregistered '
                         'address')
            label = args.label
    else:
        sys.exit('provide --ota or --addr')

    pa = load_module('patch_address', HERE / 'patch-address.py')
    patched = pa.patch_so(base, BASE_ADDR, addr)
    if patched.count(WAIT_LITERAL) != 1:
        sys.exit('post-patch verification failed: wait literal disturbed')

    out_dir = args.out or (HERE / 'carriers' / label)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / 'libhwbinder_target.so'
    if out.exists():
        if out.read_bytes() == patched:
            print(f'{out} already current - nothing to do.')
            return
        if not args.force:
            sys.exit(f'{out} exists and differs; use --force to overwrite')
    out.write_bytes(patched)
    sha = hashlib.sha256(patched).hexdigest()
    print(f'wrote {out}')
    print(f'  selinux_enforcing = 0x{addr:016x}')
    print(f'  sha256            = {sha}')
    print('Register it (carriers.tsv row + stage0 gate reads it automatically):')
    print(f'    {label.upper() if not label.startswith("ps") else label}\t'
          f'{label}\t0x{addr:016x}\t{sha}')
    print('If the PS token differs from the label (one carrier serves several')
    print('versions), add one row per token.')


if __name__ == '__main__':
    main()
