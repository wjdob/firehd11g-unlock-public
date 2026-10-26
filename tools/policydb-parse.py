#!/usr/bin/env python3
"""Full Android SELinux policydb (kernel binary format) parser.

Implements the exact read sequence of the device's own kernel
(refs/kernel-7.3.1.9 .../security/selinux/ss/policydb.c, avtab.c,
conditional.c, ebitmap.c) so we can query allow rules for Amazon-private
domains (time_update, amazon_app) that never appear in the shipped CILs.

Usage:
    python policydb-parse.py <policy.bin> --src time_update
    python policydb-parse.py <policy.bin> --query time_update file cache_file
    python policydb-parse.py <policy.bin> --dump-rules time_update
"""

import argparse
import struct
import sys

POLICYDB_MAGIC = 0xF97CFF8C
POLICYDB_STRING = b'SE Linux'
POLICYDB_CONFIG_MLS = 1

# security.h
POLICYDB_VERSION_BASE = 15
POLICYDB_VERSION_BOOL = 16
POLICYDB_VERSION_IPV6 = 17
POLICYDB_VERSION_NLCLASS = 18
POLICYDB_VERSION_VALIDATETRANS = 19
POLICYDB_VERSION_MLS = 19
POLICYDB_VERSION_AVTAB = 20
POLICYDB_VERSION_RANGETRANS = 21
POLICYDB_VERSION_POLCAP = 22
POLICYDB_VERSION_PERMISSIVE = 23
POLICYDB_VERSION_BOUNDARY = 24
POLICYDB_VERSION_FILENAME_TRANS = 25
POLICYDB_VERSION_ROLETRANS = 26
POLICYDB_VERSION_NEW_OBJECT_DEFAULTS = 27
POLICYDB_VERSION_DEFAULT_TYPE = 28
POLICYDB_VERSION_CONSTRAINT_NAMES = 29
POLICYDB_VERSION_XPERMS_IOCTL = 30

SYM_COMMONS, SYM_CLASSES, SYM_ROLES, SYM_TYPES, \
    SYM_USERS, SYM_BOOLS, SYM_LEVELS, SYM_CATS = range(8)
SYM_NUM = 8

# avtab.h
AVTAB_ALLOWED = 0x0001
AVTAB_AUDITALLOW = 0x0002
AVTAB_AUDITDENY = 0x0004
AVTAB_TRANSITION = 0x0010
AVTAB_CHANGE = 0x0040
AVTAB_MEMBER = 0x0020
AVTAB_XPERMS_ALLOWED = 0x0100
AVTAB_XPERMS_AUDITALLOW = 0x0200
AVTAB_XPERMS_DONTAUDIT = 0x0400
AVTAB_XPERMS = (AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW |
                AVTAB_XPERMS_DONTAUDIT)
AVTAB_AV = (AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY)
AVTAB_TYPE = (AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE)
AVTAB_OPTYPE = 0x1000  # avtab.h: AVTAB_OPTYPE
AVTAB_ENABLED_OLD = 0x80000000
AVTAB_ENABLED = 0x8000

SPEC_ORDER = [AVTAB_ALLOWED, AVTAB_AUDITDENY, AVTAB_AUDITALLOW,
              AVTAB_TRANSITION, AVTAB_CHANGE, AVTAB_MEMBER,
              AVTAB_XPERMS_ALLOWED, AVTAB_XPERMS_AUDITALLOW,
              AVTAB_XPERMS_DONTAUDIT]

TYPEDATUM_PROPERTY_PRIMARY = 1
TYPEDATUM_PROPERTY_ATTRIBUTE = 2

CEXPR_NOT = 0x0001
CEXPR_AND = 0x0002
CEXPR_OR = 0x0003
CEXPR_ATTR = 0x0004
CEXPR_NAMES = 0x0005


class Reader:
    def __init__(self, data):
        self.d = data
        self.pos = 0

    def u8(self):
        v = self.d[self.pos]
        self.pos += 1
        return v

    def u16(self):
        v = struct.unpack_from('<H', self.d, self.pos)[0]
        self.pos += 2
        return v

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.pos)[0]
        self.pos += 4
        return v

    def u64(self):
        v = struct.unpack_from('<Q', self.d, self.pos)[0]
        self.pos += 8
        return v

    def raw(self, n):
        b = self.d[self.pos:self.pos + n]
        if len(b) < n:
            raise EOFError('truncated policy')
        self.pos += n
        return b

    def str_(self, n):
        return self.raw(n).decode('latin-1')


class PolicyDb:
    def __init__(self, data):
        self.r = Reader(data)
        self.types = {}          # index -> name
        self.types_by_name = {}  # name -> index
        self.classes = {}        # index -> name
        self.classes_by_name = {}
        self.commons = {}
        self.perms_by_class = {}  # class index -> {perm bit -> name}
        self.av = []             # (src, tgt, cls, specified, data)
        self.cond_av = []
        self.permissive = set()
        self._parse()

    # ---- header ----
    def _parse(self):
        r = self.r
        magic = r.u32()
        if magic != POLICYDB_MAGIC:
            sys.exit(f'bad magic 0x{magic:08x}')
        slen = r.u32()
        s = r.raw(slen)
        if s != POLICYDB_STRING:
            sys.exit(f'unexpected policydb string: {s!r}')
        self.version = r.u32()
        config = r.u32()
        self.mls = bool(config & POLICYDB_CONFIG_MLS)
        sym_num = r.u32()
        ocon_num = r.u32()
        if self.version >= POLICYDB_VERSION_POLCAP:
            self._ebitmap()
        if self.version >= POLICYDB_VERSION_PERMISSIVE:
            self.permissive = self._ebitmap()
        if sym_num != SYM_NUM:
            sys.exit(f'unexpected sym_num {sym_num}')

        self._read_symtabs()
        self._read_avtab()
        if self.version >= POLICYDB_VERSION_BOOL:
            self._read_cond_list()
        self._read_role_trans()
        self._read_role_allow()
        self._read_filename_trans()
        self._read_ocontexts()
        self._read_genfs()
        self._read_range_trans()
        self._read_type_attr_map()

    def _read_role_trans(self):
        r = self.r
        nel = r.u32()
        for _ in range(nel):
            r.u32(); r.u32(); r.u32()
            if self.version >= POLICYDB_VERSION_ROLETRANS:
                r.u32()

    def _read_role_allow(self):
        r = self.r
        nel = r.u32()
        for _ in range(nel):
            r.u32(); r.u32()

    def _read_filename_trans(self):
        r = self.r
        if self.version < POLICYDB_VERSION_FILENAME_TRANS:
            return
        nel = r.u32()
        for _ in range(nel):
            len_ = r.u32()
            r.str_(len_)
            r.u32(); r.u32(); r.u32(); r.u32()

    def _read_ocontexts(self):
        r = self.r
        for i in range(7):  # OCON_NUM
            nel = r.u32()
            for _ in range(nel):
                if i == 0:  # OCON_ISID
                    r.u32()
                    self._context()
                elif i in (1, 2):  # OCON_FS, OCON_NETIF
                    len_ = r.u32()
                    r.str_(len_)
                    self._context()
                    self._context()
                elif i == 3:  # OCON_PORT
                    r.u32(); r.u32(); r.u32()
                    self._context()
                elif i == 4:  # OCON_NODE
                    r.raw(8)
                    self._context()
                elif i == 5:  # OCON_FSUSE
                    r.u32()
                    len_ = r.u32()
                    r.str_(len_)
                    self._context()
                elif i == 6:  # OCON_NODE6
                    r.raw(32)
                    self._context()

    def _context(self):
        r = self.r
        r.u32(); r.u32(); r.u32()  # user, role, type
        if self.version >= POLICYDB_VERSION_MLS:
            self._mls_range()

    def _read_genfs(self):
        r = self.r
        nel = r.u32()
        for _ in range(nel):
            len_ = r.u32()
            r.str_(len_)
            nel2 = r.u32()
            for _ in range(nel2):
                len_ = r.u32()
                r.str_(len_)
                r.u32()  # sclass
                self._context()

    def _read_range_trans(self):
        r = self.r
        if self.version < POLICYDB_VERSION_MLS:
            return
        nel = r.u32()
        for _ in range(nel):
            r.u32(); r.u32()
            if self.version >= POLICYDB_VERSION_RANGETRANS:
                r.u32()
            self._mls_range()

    def _read_type_attr_map(self):
        r = self.r
        self.type_attrs = {}  # type index -> set of attribute indices
        for i in range(self.n_types):
            if self.version >= POLICYDB_VERSION_AVTAB:
                bits = self._ebitmap()
            else:
                bits = set()
            bits.add(i)  # degenerate self-membership
            self.type_attrs[i] = bits

    # ---- ebitmap ----
    def _ebitmap(self):
        r = self.r
        mapunit = r.u32()
        highbit = r.u32()
        count = r.u32()
        if mapunit != 64:
            sys.exit(f'ebitmap mapunit {mapunit} != 64')
        bits = set()
        for _ in range(count):
            startbit = r.u32()
            map = r.u64()
            for i in range(64):
                if map & (1 << i):
                    bits.add(startbit + i)
        return bits

    # ---- symtabs ----
    def _read_symtabs(self):
        r = self.r
        for i in range(SYM_NUM):
            nprim = r.u32()
            nel = r.u32()
            if i == SYM_TYPES:
                self.n_types = nprim
            for _ in range(nel):
                if i == SYM_COMMONS:
                    self._read_common()
                elif i == SYM_CLASSES:
                    self._read_class()
                elif i == SYM_ROLES:
                    self._read_role()
                elif i == SYM_TYPES:
                    self._read_type()
                elif i == SYM_USERS:
                    self._read_user()
                elif i == SYM_BOOLS:
                    self._read_bool()
                elif i == SYM_LEVELS:
                    self._read_sens()
                elif i == SYM_CATS:
                    self._read_cat()

    def _read_common(self):
        r = self.r
        len_ = r.u32()
        value = r.u32()
        nprim = r.u32()
        nel = r.u32()
        name = r.str_(len_)
        perms = {}
        for _ in range(nel):
            plen = r.u32()
            pval = r.u32()
            perms[pval] = r.str_(plen)
        self.commons[name] = (value, perms)

    def _read_class(self):
        r = self.r
        len_ = r.u32()
        len2 = r.u32()
        value = r.u32()
        nprim = r.u32()
        nel = r.u32()
        ncons = r.u32()
        name = r.str_(len_)
        comkey = r.str_(len2) if len2 else None
        perms = {}
        for _ in range(nel):
            plen = r.u32()
            pval = r.u32()
            perms[pval] = r.str_(plen)
        if comkey:
            _, common_perms = self.commons[comkey]
            perms = {**common_perms, **perms}
        self._read_constraints(ncons)
        if self.version >= POLICYDB_VERSION_VALIDATETRANS:
            n = r.u32()
            self._read_constraints(n)
        if self.version >= POLICYDB_VERSION_NEW_OBJECT_DEFAULTS:
            r.u32(); r.u32(); r.u32()
        if self.version >= POLICYDB_VERSION_DEFAULT_TYPE:
            r.u32()
        self.classes[value] = name
        self.classes_by_name[name] = value
        self.perms_by_class[value] = perms

    def _read_constraints(self, ncons):
        r = self.r
        for _ in range(ncons):
            r.u32()  # permissions
            nexpr = r.u32()
            for _ in range(nexpr):
                expr_type = r.u32()
                attr = r.u32()
                op = r.u32()
                if expr_type == CEXPR_NAMES:
                    self._ebitmap()
                    if self.version >= POLICYDB_VERSION_CONSTRAINT_NAMES:
                        self._ebitmap()  # type_names.types
                        self._ebitmap()  # type_names.negset
                        r.u32()          # type_names.flags

    def _read_role(self):
        r = self.r
        len_ = r.u32()
        value = r.u32()
        if self.version >= POLICYDB_VERSION_BOUNDARY:
            r.u32()
        r.str_(len_)
        self._ebitmap()  # dominates
        self._ebitmap()  # types

    def _read_type(self):
        r = self.r
        len_ = r.u32()
        value = r.u32()
        if self.version >= POLICYDB_VERSION_BOUNDARY:
            prop = r.u32()
            r.u32()  # bounds
            is_attr = bool(prop & TYPEDATUM_PROPERTY_ATTRIBUTE)
        else:
            is_attr = False
        name = r.str_(len_)
        self.types[value] = name
        self.types_by_name[name] = value
        self.type_is_attr = getattr(self, 'type_is_attr', {})
        self.type_is_attr[value] = is_attr

    def _read_user(self):
        r = self.r
        len_ = r.u32()
        value = r.u32()
        if self.version >= POLICYDB_VERSION_BOUNDARY:
            r.u32()
        r.str_(len_)
        self._ebitmap()  # roles
        if self.version >= POLICYDB_VERSION_MLS:
            self._mls_range()
            self._mls_level()

    def _read_bool(self):
        r = self.r
        value = r.u32()
        state = r.u32()
        len_ = r.u32()
        r.str_(len_)

    def _read_sens(self):
        r = self.r
        len_ = r.u32()
        isalias = r.u32()
        r.str_(len_)
        self._mls_level()

    def _read_cat(self):
        r = self.r
        len_ = r.u32()
        value = r.u32()
        isalias = r.u32()
        r.str_(len_)

    def _mls_range(self):
        r = self.r
        items = r.u32()
        if items > 2:
            sys.exit('mls range overflow')
        r.raw(items * 4)
        self._ebitmap()
        if items > 1:
            self._ebitmap()

    def _mls_level(self):
        r = self.r
        r.u32()  # sens
        self._ebitmap()

    # ---- avtab ----
    def _read_avtab(self):
        r = self.r
        nel = r.u32()
        for _ in range(nel):
            self._read_avtab_entry(cond=False)

    def _read_avtab_entry(self, cond):
        r = self.r
        src = r.u16()
        tgt = r.u16()
        cls = r.u16()
        specified = r.u16()
        m_compat = False
        if specified & AVTAB_OPTYPE and self.version == POLICYDB_VERSION_XPERMS_IOCTL:
            specified = specified >> 4  # avtab_optype_to_xperms
            m_compat = True
        if specified & AVTAB_XPERMS:
            first = r.u8()  # xperms.specified (or driver in M-compat)
            if m_compat:
                driver = first
            else:
                driver = r.u8()
            r.raw(32)  # 8 x u32 perms
            data = None
        else:
            data = r.u32()
        entry = (src, tgt, cls, specified, data)
        if cond:
            self.cond_av.append(entry)
        else:
            self.av.append(entry)

    def _read_cond_list(self):
        r = self.r
        ncond = r.u32()
        for _ in range(ncond):
            cur_state = r.u32()
            nexpr = r.u32()
            for _ in range(nexpr):
                r.u32(); r.u32()  # expr_type, bool
            for _ in range(2):  # true_list, false_list
                n = r.u32()
                for _ in range(n):
                    self._read_avtab_entry(cond=True)

    # ---- queries ----
    def type_index(self, name):
        return self.types_by_name.get(name)

    def class_index(self, name):
        return self.classes_by_name.get(name)

    def _expand(self, index):
        """The type itself plus every attribute it is a member of."""
        return self.type_attrs.get(index, {index})

    def query(self, src_name, cls_name, tgt_name):
        """Attribute-aware: matches allow rules written against any attribute
        the source or target type belongs to (e.g. 'allow domain cache_file')."""
        si = self.types_by_name.get(src_name)
        ti = self.types_by_name.get(tgt_name)
        ci = self.classes_by_name.get(cls_name)
        if si is None or ti is None or ci is None:
            missing = [n for n, i in ((src_name, si), (tgt_name, ti),
                                       (cls_name, ci)) if i is None]
            return None, f'unknown symbol(s): {", ".join(missing)}'
        src_set = self._expand(si)
        tgt_set = self._expand(ti)
        perms = []
        for (src, tgt, cls, specified, data) in self.av:
            if (src in src_set and tgt in tgt_set and cls == ci
                    and specified & AVTAB_ALLOWED):
                perms.extend(self.perm_names(cls, data))
        return sorted(set(perms)), None

    def perm_names(self, cls, data):
        names = []
        perms = self.perms_by_class.get(cls, {})
        for bit in range(32):
            if data & (1 << bit):
                names.append(perms.get(bit + 1, f'bit{bit + 1}'))
        return names

    def rules_for_source(self, src_name):
        """All allow rules whose source expands to src_name (incl. attributes)."""
        si = self.types_by_name.get(src_name)
        if si is None:
            return None
        src_set = self._expand(si)
        out = []
        for (src, tgt, cls, specified, data) in self.av:
            if src in src_set and specified & AVTAB_ALLOWED:
                tgt_name = self.types.get(tgt, f'?{tgt}')
                cls_name = self.classes.get(cls, f'?{cls}')
                perms = self.perm_names(cls, data)
                out.append((self.types.get(src, f'?{src}'), tgt_name,
                            cls_name, perms))
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('policy')
    ap.add_argument('--src', help='dump all allow rules with this source')
    ap.add_argument('--query', nargs=3, metavar=('SRC', 'CLASS', 'TARGET'),
                    help='query allow perms: SRC CLASS TARGET')
    ap.add_argument('--list-types', action='store_true')
    ap.add_argument('--list-classes', action='store_true')
    args = ap.parse_args()

    pol = PolicyDb(open(args.policy, 'rb').read())
    print(f'version={pol.version} mls={pol.mls} types={len(pol.types)} '
          f'classes={len(pol.classes)} av_rules={len(pol.av)} '
          f'cond_rules={len(pol.cond_av)}', file=sys.stderr)

    if args.list_types:
        for name in sorted(pol.types_by_name):
            print(name)
    if args.list_classes:
        for name in sorted(pol.classes_by_name):
            print(name)
    if args.src:
        rules = pol.rules_for_source(args.src)
        if rules is None:
            sys.exit(f'unknown type: {args.src}')
        for tgt, cls, perms in sorted(rules):
            print(f'allow {args.src} {tgt}:{cls} {{ {", ".join(perms)} }}')
    if args.query:
        src, cls, tgt = args.query
        perms, err = pol.query(src, cls, tgt)
        if err:
            sys.exit(err)
        print(f'allow {src} {tgt}:{cls} {{ {", ".join(perms)} }}')


if __name__ == '__main__':
    main()
