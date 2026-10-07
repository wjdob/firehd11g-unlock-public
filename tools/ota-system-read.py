#!/usr/bin/env python3
"""Read files out of an OTA system.new.dat without materializing the image.

Uses the transfer-list blockmap to translate ext4 block numbers to
new.dat offsets. Provides a minimal ext4 reader sufficient for pulling
regular files (needed: plat_mac_permissions.xml and friends).

Usage:
    python ota-system-read.py <system.new.dat> <blockmap.json> <command> ...
      ls <path>
      cat <path> > local_file
"""

import json
import struct
import sys

BLOCK = 4096

# ext4 extent tree constants (kernel Documentation/filesystems/ext4/ifork.rst)
EE_MAGIC = 0xF30A
EE_UNWRITTEN = 0x8000        # ee_len > this means "uninitialized"
INODE_IBLOCK_OFF = 40        # struct ext4_inode: i_block[15] starts here
INODE_SIZE_HI_OFF = 108      # i_size_high (for files > 4 GiB)


class Ext4Reader:
    def __init__(self, dat_path, blockmap):
        self.f = open(dat_path, 'rb')
        self.bm = {int(k): v for k, v in blockmap.items()}
        try:
            self._init_geometry()
        except BaseException:
            # Every fatal path below exits before the caller can reach close(),
            # which would leak the descriptor (and on Windows block deletion).
            self.close()
            raise

    def _init_geometry(self):
        # superblock lives at byte 1024 of the image; with 4K blocks that is
        # block 0 offset 1024 (some images: block 1). Try both.
        sb = None
        for cand in (0, 1):
            raw = self.read_block(cand)
            if raw and struct.unpack('<H', raw[1080:1082])[0] == 0xEF53:
                sb = raw[1024:]
                break
        if sb is None:
            sys.exit('ext4 superblock magic not found in block 0 or 1')
        self.inodes_per_group = struct.unpack('<I', sb[40:44])[0]
        self.blocks_per_group = struct.unpack('<I', sb[32:36])[0]
        self.inode_size = struct.unpack('<H', sb[88:90])[0]
        self.desc_size = struct.unpack('<H', sb[256:258])[0] or 32
        self.block_size = 1024 << struct.unpack('<I', sb[24:28])[0]
        self.feature_incompat = struct.unpack('<I', sb[96:100])[0]
        self.has_64bit = bool(self.feature_incompat & 0x80)
        if self.block_size != 4096:
            sys.exit(f'unexpected block size {self.block_size}')
        # Group descriptors live in the block AFTER the superblock. With 1 KiB
        # blocks the superblock occupies block 1, so the GDT starts at block 2;
        # with any larger block size the superblock is at byte 1024 inside block
        # 0 and the GDT starts at block 1. This was hardcoded to 2, which is
        # only correct for the 1 KiB case the code above already rejected.
        self.gdt_block = 2 if self.block_size == 1024 else 1

    def read_block(self, n):
        if n not in self.bm:
            sys.exit(f'block {n} not in blockmap (hole/erased)')
        self.f.seek(self.bm[n])
        return self.f.read(BLOCK)

    def group_desc(self, group):
        # The descriptor table begins at self.gdt_block (1 for 4 KiB blocks).
        tbl_block = self.gdt_block + (group * self.desc_size) // self.block_size
        off = (group * self.desc_size) % self.block_size
        raw = self.read_block(tbl_block)[off:off + self.desc_size]
        if self.has_64bit and self.desc_size >= 64:
            inode_table_hi = struct.unpack('<I', raw[40:44])[0]
        else:
            inode_table_hi = 0
        inode_table_lo = struct.unpack('<I', raw[8:12])[0]
        return inode_table_lo | (inode_table_hi << 32)

    def read_inode(self, ino):
        group = (ino - 1) // self.inodes_per_group
        idx = (ino - 1) % self.inodes_per_group
        itbl = self.group_desc(group)
        raw = self.read_block(itbl + (idx * self.inode_size) // self.block_size)
        return raw[(idx * self.inode_size) % self.block_size:][:self.inode_size]

    @staticmethod
    def file_size(raw):
        """Full file size: 64-bit when i_size_high is set (files > 4 GiB)."""
        lo = struct.unpack('<I', raw[4:8])[0]
        hi = struct.unpack('<I', raw[INODE_SIZE_HI_OFF:INODE_SIZE_HI_OFF + 4])[0]
        return lo | (hi << 32)

    def read_file_bytes(self, inode_raw, size):
        """Return the file's data blocks in order.

        The extent tree header sits at i_block[0], i.e. inode offset 40 -- not
        60. An earlier version checked the magic at 40 but walked from 60, so it
        read the header as if it were entry data.
        """
        magic = struct.unpack('<H', inode_raw[INODE_IBLOCK_OFF:INODE_IBLOCK_OFF + 2])[0]
        if magic != EE_MAGIC:
            sys.exit('not an extent-based inode (file extents only)')
        out = bytearray()
        self._walk_extents(inode_raw, INODE_IBLOCK_OFF, 0, size, out)
        return bytes(out[:size])

    def _extent_header(self, node, off):
        """(entries, depth) for the extent header at node[off:off+12].

        Layout per the kernel's ifork reference:
            eh_magic(2) eh_entries(2) eh_max(2) eh_depth(2) eh_generation(4)
        The old code unpacked four half-words and called the fourth one `depth`,
        which is actually eh_generation -- so depth was always the generation
        counter and index nodes were never recursed into.
        """
        if len(node) < off + 12:
            sys.exit('extent header truncated')
        magic, entries, maximum, depth = struct.unpack('<HHHH', node[off:off + 8])
        if magic != EE_MAGIC:
            sys.exit(f'bad extent magic 0x{magic:04x} at inode/file offset {off}')
        if entries > maximum:
            sys.exit(f'extent header entries({entries}) > max({maximum})')
        return entries, depth

    def _walk_extents(self, node, off, expected_block, size, out):
        """Append the data described by the extent tree at node[off:].

        Fails closed on anything it cannot represent exactly. For an evidence
        tool the dangerous failure is not an error -- it is returning plausible
        bytes that are not the file's contents, so a hole or an uninitialized
        extent stops the read instead of being filled with zeros.
        """
        entries, depth = self._extent_header(node, off)
        for i in range(entries):
            p = off + 12 + i * 12
            if p + 12 > len(node):
                sys.exit('extent entry truncated')
            if depth == 0:
                # struct ext4_extent: ee_block(4) ee_len(2) ee_start_hi(2) ee_start_lo(4)
                ee_block, ee_len, hi, lo = struct.unpack('<IHHI', node[p:p + 12])
                start = lo | (hi << 32)
                if ee_len > EE_UNWRITTEN:
                    sys.exit(
                        'uninitialized (unwritten) extent at logical block %d: '
                        'its contents are not on disk, so refusing to emit zeros '
                        'as if they were file data' % ee_block)
                if ee_block != expected_block:
                    sys.exit(
                        'hole in file: expected logical block %d, next extent '
                        'starts at %d -- refusing to fabricate the gap'
                        % (expected_block, ee_block))
                for k in range(ee_len):
                    out.extend(self.read_block(start + k))
                    if len(out) >= size:
                        return
                expected_block += ee_len
            else:
                # struct ext4_extent_idx: ei_block(4) ei_leaf_lo(4) ei_leaf_hi(2) unused(2)
                ei_block, leaf_lo, leaf_hi = struct.unpack('<IIH', node[p:p + 10])
                child = self.read_block(leaf_lo | (leaf_hi << 32))
                self._walk_extents(child, 0, ei_block, size, out)
                if len(out) >= size:
                    return

    def lookup(self, path):
        ino = 2  # root
        parts = [p for p in path.strip('/').split('/') if p]
        for comp in parts:
            inode_raw = self.read_inode(ino)
            size = self.file_size(inode_raw)
            data = self.read_file_bytes(inode_raw, size)
            found = None
            pos = 0
            while pos < len(data):
                ino_le, rec_len, name_len, ftype = struct.unpack(
                    '<IHBB', data[pos:pos + 8])
                if rec_len == 0:
                    break
                name = data[pos + 8:pos + 8 + name_len].decode()
                if name == comp:
                    found = ino_le
                    break
                pos += rec_len
            if not found:
                return None
            ino = found
        return ino

    def close(self):
        if getattr(self, 'f', None) is not None:
            self.f.close()
            self.f = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def stat(self, path):
        ino = self.lookup(path)
        if not ino:
            return None
        raw = self.read_inode(ino)
        mode = struct.unpack('<H', raw[0:2])[0]
        size = self.file_size(raw)
        return {'ino': ino, 'mode': mode, 'size': size}

    def cat(self, path):
        ino = self.lookup(path)
        if not ino:
            return None
        raw = self.read_inode(ino)
        return self.read_file_bytes(raw, self.file_size(raw))

    def ls(self, path):
        ino = self.lookup(path)
        if not ino:
            return None
        raw = self.read_inode(ino)
        data = self.read_file_bytes(raw, self.file_size(raw))
        out = []
        pos = 0
        while pos < len(data):
            ino_le, rec_len, name_len, ftype = struct.unpack(
                '<IHBB', data[pos:pos + 8])
            if rec_len == 0:
                break
            name = data[pos + 8:pos + 8 + name_len].decode()
            if name not in ('.', '..'):
                out.append((name, ftype, ino_le))
            pos += rec_len
        return out


def _build_synthetic_ext4(path, blockmap_out, file_size, extents, index_node=False):
    """Write a minimal one-group ext4 image with a single file at /f.

    `extents` is a list of (logical_block, length, physical_block, unwritten).
    Blocks are written contiguously so blockmap_out maps block -> block*4096.
    Returns the file's expected bytes.
    """
    import os
    B = BLOCK
    layout = {}
    b = 0
    def alloc(n=1):
        nonlocal b
        start = b
        b += n
        return start

    sb_block = alloc(1)          # block 0: superblock at byte 1024
    gdt_block = alloc(1)         # block 1
    alloc(1)                     # block 2: reserved
    inode_table = alloc(4)       # blocks 3..6
    dir_block = alloc(1)         # block 7
    idx_block = alloc(1)         # block 8 (index node, when used)
    data_blocks = []
    for _logical, length, _phys, _un in extents:
        data_blocks.append(alloc(length))

    payload = bytearray()
    for i, (logical, length, _phys, unwritten) in enumerate(extents):
        if unwritten:
            payload.extend(b'\x00' * (length * B))
        else:
            for k in range(length):
                payload.extend(bytes([(i * 37 + k) & 0xFF]) * B)
    expected = bytes(payload[:file_size])

    img = bytearray(b * B)
    # --- superblock ---
    sb = bytearray(1024)
    struct.pack_into('<I', sb, 24, 2)          # s_log_block_size -> 1024<<2 = 4096
    struct.pack_into('<I', sb, 32, 8192)       # s_blocks_per_group
    struct.pack_into('<I', sb, 40, 16)         # s_inodes_per_group (must cover ino 11 in group 0)
    struct.pack_into('<H', sb, 56, 0xEF53)     # magic (read at +1080)
    struct.pack_into('<H', sb, 88, 256)        # s_inode_size
    struct.pack_into('<I', sb, 96, 0)          # feature_incompat
    struct.pack_into('<H', sb, 256, 64)        # s_desc_size
    img[1024:1024 + len(sb)] = sb
    # --- group descriptor (inode table lo at +8) ---
    struct.pack_into('<I', img, gdt_block * B + 8, inode_table)
    # --- inode 2: root directory (mode dir, extent -> dir_block) ---
    ino2 = inode_table * B + 1 * 256
    struct.pack_into('<H', img, ino2 + 0, 0o040755)
    struct.pack_into('<I', img, ino2 + 4, B)
    struct.pack_into('<H', img, ino2 + INODE_IBLOCK_OFF, EE_MAGIC)
    struct.pack_into('<H', img, ino2 + INODE_IBLOCK_OFF + 2, 1)   # entries
    struct.pack_into('<H', img, ino2 + INODE_IBLOCK_OFF + 4, 4)   # max
    struct.pack_into('<H', img, ino2 + INODE_IBLOCK_OFF + 6, 0)   # depth
    struct.pack_into('<IHHI', img, ino2 + INODE_IBLOCK_OFF + 12,
                     0, 1, 0, dir_block)
    # --- root dir data: one entry "f" -> inode 11 ---
    struct.pack_into('<IHBB', img, dir_block * B, 11, B, 1, 1)
    img[dir_block * B + 8] = ord('f')
    # --- inode 11: regular file with the supplied extent tree ---
    ino11 = inode_table * B + 10 * 256
    struct.pack_into('<H', img, ino11 + 0, 0o100644)
    struct.pack_into('<I', img, ino11 + 4, file_size)
    if index_node:
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF, EE_MAGIC)
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF + 2, 1)
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF + 4, 4)
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF + 6, 1)      # depth 1
        struct.pack_into('<IIH', img, ino11 + INODE_IBLOCK_OFF + 12,
                         extents[0][0], idx_block, 0)
        struct.pack_into('<H', img, idx_block * B, EE_MAGIC)
        struct.pack_into('<H', img, idx_block * B + 2, len(extents))
        struct.pack_into('<H', img, idx_block * B + 4, 4)
        struct.pack_into('<H', img, idx_block * B + 6, 0)
        base, slots = idx_block * B + 12, len(extents)
    else:
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF, EE_MAGIC)
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF + 2, len(extents))
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF + 4, 4)
        struct.pack_into('<H', img, ino11 + INODE_IBLOCK_OFF + 6, 0)
        base, slots = ino11 + INODE_IBLOCK_OFF + 12, len(extents)
    for i, (logical, length, _phys, unwritten) in enumerate(extents):
        assert i < slots, 'too many extents for the inline header'
        ee_len = length + (EE_UNWRITTEN if unwritten else 0)
        struct.pack_into('<IHHI', img, base + i * 12,
                         logical, ee_len, 0, data_blocks[i])
    # --- file data ---
    for i, (_l, length, _p, unwritten) in enumerate(extents):
        if unwritten:
            continue
        for k in range(length):
            img[(data_blocks[i] + k) * B:(data_blocks[i] + k + 1) * B] = \
                bytes([(i * 37 + k) & 0xFF]) * B

    with open(path, 'wb') as fh:
        fh.write(img)
    blockmap_out.update({n: n * B for n in range(b)})
    return expected


def selftest() -> None:
    """Round-trip real file data through the extent reader.

    Covers the four defects this tool had: header read from the wrong offset,
    depth bound to the generation half-word, a 12-byte entry unpacked as 8, and
    the group-descriptor table hardcoded to block 2. Also asserts the two
    fail-closed paths, because for an evidence tool silently returning wrong
    bytes is worse than an error.
    """
    import contextlib
    import io
    import json
    import os
    import tempfile

    def load(tmp, extents, size, index_node=False):
        dat = os.path.join(tmp, 'system.new.dat')
        bm = {}
        expected = _build_synthetic_ext4(dat, bm, size, extents, index_node)
        bm_path = os.path.join(tmp, 'blockmap.json')
        with open(bm_path, 'w') as fh:
            json.dump({str(k): v for k, v in bm.items()}, fh)
        return Ext4Reader(dat, bm), expected

    def cat_and_close(fs):
        try:
            return fs.cat('/f')
        finally:
            fs.close()

    with tempfile.TemporaryDirectory() as tmp:
        B = BLOCK
        # 1. single extent
        fs, want = load(tmp, [(0, 3, 0, False)], 3 * B)
        assert cat_and_close(fs) == want, 'single extent round-trip failed'
        # 2. fragmented: two extents
        fs, want = load(tmp, [(0, 2, 0, False), (2, 2, 0, False)], 4 * B)
        assert cat_and_close(fs) == want, 'multi-extent round-trip failed'
        # 3. size not a multiple of the block size (tail truncation)
        fs, want = load(tmp, [(0, 2, 0, False)], 2 * B - 17)
        assert cat_and_close(fs) == want, 'short file round-trip failed'
        # 4. index node (depth 1), two extents under it
        fs, want = load(tmp, [(0, 2, 0, False), (2, 1, 0, False)], 3 * B, index_node=True)
        assert cat_and_close(fs) == want, 'index-node round-trip failed'
        # 5. unwritten extent must refuse, not fabricate zeros
        fs, _ = load(tmp, [(0, 2, 0, False), (2, 1, 0, True)], 3 * B)
        try:
            cat_and_close(fs)
        except SystemExit as e:
            assert 'uninitialized' in str(e), 'wrong refusal: %s' % e
        else:
            raise AssertionError('unwritten extent was not refused')
        # 6. hole must refuse
        fs, _ = load(tmp, [(0, 1, 0, False), (5, 1, 0, False)], 2 * B)
        try:
            cat_and_close(fs)
        except SystemExit as e:
            assert 'hole' in str(e), 'wrong refusal: %s' % e
        else:
            raise AssertionError('hole was not refused')
        # 7. directory traversal still works
        fs, _ = load(tmp, [(0, 1, 0, False)], B)
        try:
            assert [n for n, _t, _i in fs.ls('/')] == ['f'], 'ls failed'
            assert fs.lookup('/f') == 11, 'lookup failed'
        finally:
            fs.close()

    print('selftest OK: extent reader round-trips single/multi/short/index-node '
          'files and refuses unwritten extents and holes')


def main():
    if '--selftest' in sys.argv:
        selftest()
        return
    if len(sys.argv) < 4:
        print(__doc__)
        print('  --selftest   build synthetic images and verify the reader')
        sys.exit(1)
    dat, bm_path, cmd = sys.argv[1], sys.argv[2], sys.argv[3]
    bm = json.load(open(bm_path))
    fs = Ext4Reader(dat, bm)
    if cmd == 'ls':
        for name, ftype, ino in fs.ls(sys.argv[4]):
            print(f'{name} type={ftype} ino={ino}')
    elif cmd == 'stat':
        print(fs.stat(sys.argv[4]))
    elif cmd == 'cat':
        data = fs.cat(sys.argv[4])
        if data is None:
            sys.exit('not found')
        sys.stdout.buffer.write(data)
    else:
        sys.exit(f'unknown command {cmd}')


if __name__ == '__main__':
    main()
