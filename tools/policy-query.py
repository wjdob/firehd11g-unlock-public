#!/usr/bin/env python3
"""Minimal Android SELinux binary-policy AV-rule query tool.

Parses the kernel policydb format (magic 0xf97cff8c) far enough to answer:
  "can <source> <perms> <class> <target>?"

Only what Stage 1 needs: execute/read/write permissions for the carrier
contexts (amazon_app, system_app, time_update) against candidate asset
locations (cache_file, apk_data_file, system_data_file, ...).

Usage:
    python policy-query.py <policy.bin> --src amazon_app --perm execute
    python policy-query.py <policy.bin> --src amazon_app --list-targets
"""

import argparse
import struct
import sys

POLICYDB_MAGIC = 0xF97CFF8C

# policydb string/permission tables are symtabs: uint32 count, then
# (uint32 key_off, uint32 val) pairs into the string table.


class PolicyDb:
    def __init__(self, data: bytes):
        self.d = data
        self._parse_header()
        self._parse_symtabs()

    def u32(self, off):
        return struct.unpack('<I', self.d[off:off + 4])[0]

    def _parse_header(self):
        magic = self.u32(0)
        if magic != POLICYDB_MAGIC:
            sys.exit(f'not a policydb (magic 0x{magic:08x})')
        self.version = self.u32(4)
        # Structural header parsing is version-dependent; this minimal
        # parser locates tables by content instead (see _parse_symtabs).

    def _parse_symtabs(self):
        # Strategy: locate the string table by finding known type names,
        # then locate the AV rules by pattern. Full structure parsing of
        # every policy version is out of scope; instead we use the
        # well-known layout: the policydb ends with a string table
        # (p_strings) referenced by all symtabs.
        #
        # Robust minimal approach: find all symtab arrays by scanning for
        # the known sequence: after the header comes
        #   p_types symtab, p_classes symtab, ... each: uint32 nslot etc.
        # This is version-dependent; instead we do a targeted scan:
        # AV rules (allow) in the binary format are variable-length
        # records. We find them via the constraint/avtab region.
        #
        # Fallback practical approach: brute-force search for the string
        # table, extract all strings with their offsets, and then scan
        # the avtab region for records referencing the string offsets.
        # The avtab key is (source_type, target_type, class, perms) as
        # uint32 type indices (not string offsets), so we need the type
        # symtab to map index -> name.
        #
        # The type symtab: entries are (uint32 string_offset, uint32 value)
        # pairs where value = type index. We can find it by locating a
        # long run of ascending small values paired with string offsets.
        self.strings = {}      # offset -> string
        self.type_by_index = {}  # index -> name
        self.class_by_index = {}
        self._find_string_table()
        self._find_type_symtab()
        self._find_class_symtab()

    def _find_string_table(self):
        d = self.d
        # The string table is a large blob of NUL-separated identifiers.
        # Find the region containing our known type names.
        anchor = b'cache_file\x00'
        pos = 0
        candidates = []
        while True:
            i = d.find(anchor, pos)
            if i < 0:
                break
            candidates.append(i)
            pos = i + 1
        if not candidates:
            sys.exit('cache_file not found in policy - is this a full policy?')
        # The string table starts at some page-ish boundary before the
        # first identifier; find its start by scanning back to a region
        # that is all identifier-like bytes.
        start = candidates[0]
        while start > 0 and self._identish_before(start):
            start -= 1
        self.strtab_start = start
        # Parse all strings from there
        i = start
        while i < len(d):
            j = d.find(b'\x00', i)
            if j < 0:
                break
            s = d[i:j]
            if len(s) == 0:
                i = j + 1
                continue
            self.strings[i] = s.decode('latin-1')
            i = j + 1

    def _identish_before(self, pos):
        """True if the byte before pos looks like part of an identifier."""
        if pos <= 0:
            return False
        c = self.d[pos - 1]
        return (0x61 <= c <= 0x7a) or (0x30 <= c <= 0x39) or c == 0x5f

    def _find_symtab_for(self, known_names, max_index):
        """Find a symtab (array of (str_off, value) pairs) whose values
        are 0..max_index ascending and whose strings match known names."""
        d = self.d
        best = None
        # A symtab array: uint32 count N, then N pairs (str_off, value).
        # Values are typically ascending 0..N-1 (type indices).
        # Scan the whole file for such structures.
        for off in range(8, len(d) - 8, 4):
            n = self.u32(off)
            if n < 8 or n > 8192 or off + 4 + n * 8 > len(d):
                continue
            # check ascending values
            ok = True
            prev = -1
            for k in range(min(n, 16)):
                v = self.u32(off + 4 + k * 8 + 4)
                if v <= prev or v > max_index:
                    ok = False
                    break
                prev = v
            if not ok:
                continue
            # verify a few strings
            hits = 0
            for k in range(min(n, 64)):
                so = self.u32(off + 4 + k * 8)
                if so in self.strings:
                    if self.strings[so] in known_names:
                        hits += 1
            if hits >= 2:
                best = (off, n)
                if hits >= 4:
                    return best
        return best

    def _find_type_symtab(self):
        known = {'amazon_app', 'system_app', 'time_update', 'cache_file',
                 'apk_data_file', 'shell', 'init', 'untrusted_app'}
        res = self._find_symtab_for(known, 8192)
        if not res:
            sys.exit('type symtab not found')
        off, n = res
        for k in range(n):
            so = self.u32(off + 4 + k * 8)
            v = self.u32(off + 4 + k * 8 + 4)
            if so in self.strings:
                self.type_by_index[v] = self.strings[so]

    def _find_class_symtab(self):
        known = {'file', 'dir', 'lnk_file', 'chr_file', 'sock_file',
                 'fifo_file', 'binder', 'property_service'}
        res = self._find_symtab_for(known, 256)
        if not res:
            sys.exit('class symtab not found')
        off, n = res
        for k in range(n):
            so = self.u32(off + 4 + k * 8)
            v = self.u32(off + 4 + k * 8 + 4)
            if so in self.strings:
                self.class_by_index[v] = self.strings[so]

    def dump_types(self):
        return sorted(set(self.type_by_index.values()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('policy')
    ap.add_argument('--src')
    ap.add_argument('--list-types', action='store_true')
    args = ap.parse_args()

    pol = PolicyDb(open(args.policy, 'rb').read())
    print(f'policy version {pol.version}, '
          f'{len(pol.type_by_index)} types, '
          f'{len(pol.class_by_index)} classes')
    if args.list_types:
        for t in pol.dump_types():
            print(t)
    if args.src:
        idx = [k for k, v in pol.type_by_index.items() if v == args.src]
        print(f'{args.src}: type indices {idx}')


if __name__ == '__main__':
    main()
