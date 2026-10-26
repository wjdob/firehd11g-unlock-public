#!/usr/bin/env python3
"""Extract kernel data-symbol addresses from an Amazon Fire HD 10 OTA image.

Pipeline: OTA zip -> boot.img -> gzip kernel -> raw ARM64 Image ->
vmlinux-to-elf (kallsyms) -> capstone adrp-scan for data symbols.

Primary target: selinux_enforcing (the SnuSnuRoot hwbinder NULL-write
destination). Because CONFIG_KALLSYMS_ALL is unset, data symbols are absent
from kallsyms; they are recovered by scanning .kernel for adrp+ldr/str
pairs and counting references (the SELinux hooks read it ~7 times).

Usage:
    python extract-symbols.py <ota.bin> <output-dir>

Requires: pip install vmlinux-to-elf peewee lz4 click capstone
(the vmlinux-to-elf console script must be on PATH, or pass --elf-tool).
"""

import argparse
import re
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

KERNEL_VA_BASE = 0xFFFFFF8008080000  # trona LK boot, no KASLR seed
KERNEL_SEC_FILE_OFF = 0x240          # .kernel section file offset in the
                                     # vmlinux-to-elf output ELF


def ota_to_bootimg(ota_path: Path, out_dir: Path) -> Path:
    with zipfile.ZipFile(ota_path) as z:
        names = z.namelist()
        if 'boot.img' not in names:
            sys.exit('OTA does not contain boot.img')
        z.extract('boot.img', out_dir)
    return out_dir / 'boot.img'


def bootimg_to_raw_kernel(bootimg: Path, out_dir: Path) -> Path:
    data = bootimg.read_bytes()
    if data[:8] != b'ANDROID!':
        sys.exit('not an Android boot image')
    kernel_size = struct.unpack('<I', data[8:12])[0]
    page_size = struct.unpack('<I', data[36:40])[0]
    blob = data[page_size:page_size + kernel_size]
    if blob[:2] != b'\x1f\x8b':
        sys.exit('kernel blob is not gzip (unsupported)')
    import zlib
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    raw = d.decompress(blob)
    if raw[0x38:0x3C] != b'ARM\x64':
        sys.exit('decompressed image lacks ARM64 magic at 0x38')
    out = out_dir / 'kernel.img'
    out.write_bytes(raw)
    return out


def raw_to_elf(kernel: Path, out_dir: Path, elf_tool: str) -> Path:
    elf = out_dir / 'vmlinux.elf'
    tool = elf_tool
    if tool == 'vmlinux-to-elf':
        # Windows: the console script lives in the user Scripts dir, not PATH
        import shutil
        if not shutil.which(tool):
            for base in (Path.home() / 'AppData' / 'Roaming' / 'Python',
                         Path(sys.prefix)):
                cand = base / 'Python314' / 'Scripts' / 'vmlinux-to-elf.exe'
                if cand.exists():
                    tool = str(cand)
                    break
                cand = base / 'Scripts' / 'vmlinux-to-elf.exe'
                if cand.exists():
                    tool = str(cand)
                    break
    cmd = [tool, str(kernel), str(elf)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not elf.exists():
        sys.exit(f'vmlinux-to-elf failed:\n{r.stdout}\n{r.stderr}')
    return elf


def load_sections(elf_bytes: bytes):
    e_shoff = struct.unpack('<Q', elf_bytes[0x28:0x30])[0]
    e_shentsize = struct.unpack('<H', elf_bytes[0x3A:0x3C])[0]
    e_shnum = struct.unpack('<H', elf_bytes[0x3C:0x3E])[0]
    e_shstrndx = struct.unpack('<H', elf_bytes[0x3E:0x40])[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size,
         link, info, align, entsize) = struct.unpack('<IIQQQQIIQQ', elf_bytes[off:off + 64])
        secs.append((name, typ, addr, offset, size))
    shstr_off = secs[e_shstrndx][3]

    def secname(n):
        end = elf_bytes.index(b'\x00', shstr_off + n)
        return elf_bytes[shstr_off + n:end].decode()
    return [(secname(s[0]),) + s[1:] for s in secs]


def load_symbols(elf_bytes: bytes, sections):
    symtab = strtab = None
    for s in sections:
        if s[0] == '.symtab':
            symtab = s
        elif s[0] == '.strtab':
            strtab = s
    if not symtab:
        sys.exit('no .symtab (kallsyms reconstruction failed?)')
    _, _, _, stoff, ssize = symtab
    stroff = strtab[3]
    syms = {}
    entsize = 24
    for i in range(ssize // entsize):
        o = stoff + i * entsize
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
            '<IBBHQQ', elf_bytes[o:o + 24])
        if st_name == 0:
            continue
        end = elf_bytes.index(b'\x00', stroff + st_name)
        nm = elf_bytes[stroff + st_name:end].decode(errors='replace')
        syms[nm] = st_value
    return syms


def scan_adrp_refs(code: bytes, code_va: int, target: int):
    """Find adrp Xd, page ; ldr/str Xt, [Xd, #off] pairs hitting target."""
    page = target & ~0xFFF
    offset = target & 0xFFF
    hits = []
    for i in range(0, len(code) - 8, 4):
        w = struct.unpack('<I', code[i:i + 4])[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        pc = code_va + i
        p = ((pc >> 12) << 12) + (imm << 12)
        if p != page:
            continue
        w2 = struct.unpack('<I', code[i + 4:i + 8])[0]
        rn = (w2 >> 5) & 0x1F
        if rn != rd:
            continue
        for base, scale, kind in [
            (0xB9400000, 4, 'ldr32'), (0xB9000000, 4, 'str32'),
            (0xF9400000, 8, 'ldr64'), (0xF9000000, 8, 'str64'),
        ]:
            if (w2 & 0xFFC00000) == base:
                imm12 = ((w2 >> 10) & 0xFFF) * scale
                if imm12 == offset:
                    hits.append((pc, kind))
    return hits


def find_selinux_enforcing(elf_bytes: bytes, sections, syms):
    """Locate selinux_enforcing DEFINITIVELY via enforcing_setup.

    enforcing_setup(char *str) is the kernel cmdline handler for
    'enforcing='; its entire body is:
        get_option(&str, &enforcing); selinux_enforcing = !enforcing;
    The single str (store) in that tiny function targets selinux_enforcing.
    This is unambiguous, no heuristic ranking required.

    Fallback (if enforcing_setup is absent from kallsyms): rank globals read
    with the 'if (!x) allow' cbz pattern inside the SELinux text range.
    """
    kernel_sec = next(s for s in sections if s[0] == '.kernel')
    _, kaddr, koff, ksize = kernel_sec[1], kernel_sec[2], kernel_sec[3], kernel_sec[4]
    code = elf_bytes[koff:koff + ksize]

    if 'enforcing_setup' in syms:
        fn = syms['enforcing_setup']
        off = fn - kaddr
        # scan the function body (until ret) for adrp + str w
        adrp = {}
        i = 0
        while i < 0x100:
            w = struct.unpack('<I', code[off + i:off + i + 4])[0]
            if (w & 0x9F000000) == 0x90000000:
                rd = w & 0x1F
                immlo = (w >> 29) & 3
                immhi = (w >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= (1 << 21)
                pc = kaddr + off + i
                adrp[rd] = ((pc >> 12) << 12) + (imm << 12)
            # str w, [x, #imm] : 1011 1001 00 imm12 Rn Rt
            elif (w & 0xFFC00000) == 0xB9000000:
                rn = (w >> 5) & 0x1F
                imm12 = ((w >> 10) & 0xFFF) * 4
                if rn in adrp:
                    target = adrp[rn] + imm12
                    refs = scan_adrp_refs(code, kaddr, target)
                    return [(len(refs), target, refs, 'enforcing_setup')]
            # RET (x30): 0xd65f03c0
            elif w == 0xD65F03C0:
                break
            i += 4

    # Fallback: SELinux-text-range heuristic (see git history for why the
    # naive whole-kernel scan is insufficient)
    anchors = [syms[n] for n in ('avc_denied', 'selinux_capable',
                                  'security_load_policy',
                                  'selinux_complete_init') if n in syms]
    if not anchors:
        sys.exit('neither enforcing_setup nor SELinux anchors in kallsyms')
    lo = min(anchors) - 0x20000
    hi = max(anchors) + 0x20000
    from collections import Counter
    reads = Counter()
    for i in range(0, len(code) - 12, 4):
        pc = kaddr + i
        if not (lo <= pc <= hi):
            continue
        w = struct.unpack('<I', code[i:i + 4])[0]
        if (w & 0x9F000000) != 0x90000000:
            continue
        rd = w & 0x1F
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= (1 << 21)
        page = ((pc >> 12) << 12) + (imm << 12)
        w2 = struct.unpack('<I', code[i + 4:i + 8])[0]
        w3 = struct.unpack('<I', code[i + 8:i + 12])[0]
        if (w2 & 0xFFC00000) == 0xB9400000 and (w3 & 0xFF000000) == 0x34000000:
            rn = (w2 >> 5) & 0x1F
            if rn != rd:
                continue
            imm12 = ((w2 >> 10) & 0xFFF) * 4
            rt = w2 & 0x1F
            if (w3 & 0x1F) == rt:
                reads[page + imm12] += 1
    ranked = []
    for addr in reads:
        refs = scan_adrp_refs(code, kaddr, addr)
        selinux_refs = [r for r in refs if lo <= r[0] <= hi]
        if len(selinux_refs) >= 2:
            ranked.append((len(selinux_refs), addr, refs, 'heuristic'))
    ranked.sort(reverse=True)
    return ranked


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('ota', type=Path)
    ap.add_argument('out_dir', type=Path)
    ap.add_argument('--elf-tool', default='vmlinux-to-elf')
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    bootimg = ota_to_bootimg(args.ota, args.out_dir)
    kernel = bootimg_to_raw_kernel(bootimg, args.out_dir)
    elf = raw_to_elf(kernel, args.out_dir, args.elf_tool)
    elf_bytes = elf.read_bytes()

    sections = load_sections(elf_bytes)
    syms = load_symbols(elf_bytes, sections)

    print(f'== {args.ota.name} ==')
    print(f'symbols: {len(syms)}')
    for name in ['commit_creds', 'avc_denied', 'selinux_capable',
                 'kbase_ioctl', 'kbase_mmap']:
        if name in syms:
            print(f'  {name:20s} 0x{syms[name]:016x}')

    print('\nselinux_enforcing candidates:')
    ranked = find_selinux_enforcing(elf_bytes, sections, syms)
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
        print('Cross-check: PS7326=0xffffff8009969668, '
              'PS7331=0xffffff8009971668 (same BSS region expected).')


if __name__ == '__main__':
    main()
