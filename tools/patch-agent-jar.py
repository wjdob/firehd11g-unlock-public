#!/usr/bin/env python3
"""Patch agent.jar's hardcoded asset path for the PS7319 layout.

The upstream agent.jar embeds ASSET_DIR = /data/securedStorageLocation/
codex.amazon.jni.v51 (49 chars) and the JNI prefix (69 chars). On PS7319
that location is not writable by any reachable staging channel, so the
assets live in the webview app's own data dir instead.

The replacement path is chosen to be EXACTLY the same length, so the dex
string_data_item layout (uleb128 length + MUTF-8 + NUL) stays byte-aligned
and no offsets shift:

    old: /data/securedStorageLocation/codex.amazon.jni.v51          (49)
    new: /data/user/0/com.amazon.webview.chromium/files/sn          (49)

DEX integrity: the header carries an Adler-32 checksum (offset 8, over
bytes[12:]) and a SHA-1 signature (offset 12, over bytes[32:]). Both are
recomputed after patching so ART accepts the file.

Usage:
    python tools/patch-agent-jar.py <in.jar> <out.jar>
"""

import hashlib
import io
import struct
import sys
import zipfile
import zlib

OLD_ASSET = b'/data/securedStorageLocation/codex.amazon.jni.v51'
NEW_ASSET = b'/data/user/0/com.amazon.webview.chromium/files/sn'
OLD_JNI_PREFIX = OLD_ASSET + b'/libhwbinder_target.'
NEW_JNI_PREFIX = NEW_ASSET + b'/libhwbinder_target.'

DEX_MAGIC = b'dex\n'


def patch_dex(data: bytes) -> bytes:
    if not data.startswith(DEX_MAGIC):
        sys.exit('not a dex file')
    if len(OLD_ASSET) != len(NEW_ASSET):
        sys.exit('replacement path length mismatch')
    if len(OLD_JNI_PREFIX) != len(NEW_JNI_PREFIX):
        sys.exit('replacement JNI prefix length mismatch')

    hits = 0
    for old, new in ((OLD_JNI_PREFIX, NEW_JNI_PREFIX), (OLD_ASSET, NEW_ASSET)):
        # Longest first so the JNI prefix is not partially rewritten.
        start = 0
        while True:
            idx = data.find(old, start)
            if idx < 0:
                break
            data = data[:idx] + new + data[idx + len(old):]
            hits += 1
            start = idx + len(new)
    if hits == 0:
        sys.exit('no hardcoded asset path found in dex')

    buf = bytearray(data)
    # signature: SHA-1 over everything after the 32-byte header prefix
    sig = hashlib.sha1(bytes(buf[32:])).digest()
    buf[12:32] = sig
    # checksum: Adler-32 over everything after the checksum field
    chk = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', buf, 8, chk)
    return bytes(buf)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    with zipfile.ZipFile(src) as zin:
        names = zin.namelist()
        if 'classes.dex' not in names:
            sys.exit('classes.dex not found in jar')
        dex = zin.read('classes.dex')
        patched = patch_dex(dex)
        with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED) as zout:
            for name in names:
                payload = patched if name == 'classes.dex' else zin.read(name)
                zout.writestr(name, payload)
    print(f'patched {src} -> {dst}')
    print(f'  asset dir: {NEW_ASSET.decode()}')
    print(f'  jni prefix: {NEW_JNI_PREFIX.decode()}')


if __name__ == '__main__':
    main()