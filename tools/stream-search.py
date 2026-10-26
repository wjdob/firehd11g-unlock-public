#!/usr/bin/env python3
"""Stream-search a binary file for a byte pattern with bounded memory.

Single forward pass, fixed-size chunks with overlap, no re-reading.
Guaranteed termination: pos strictly increases every iteration.

Usage:
    python stream-search.py <file> <pattern> [chunk_mb]
"""

import sys
import time


def stream_search(path: str, needle: bytes, chunk_size: int = 8 * 1024 * 1024):
    """Yield byte offsets of needle occurrences in path.

    Reads forward once. Each iteration reads at most chunk_size bytes and
    retains an overlap of len(needle)-1 bytes so a pattern straddling a
    boundary is still found.

    Offset accounting: `pos` is the count of bytes read from the file *before*
    this chunk, so chunk[0] lives at file offset `pos`. The buffer is
    `tail + chunk`, and tail[0] is at `pos - len(tail)`, so a match at buffer
    index `idx` is at `pos - len(tail) + idx`.

    An earlier version advanced `pos` by the *non-overlapping* consumed count
    while still subtracting `len(tail)` from the reported offset, which made
    every hit after the first chunk wrong by len(needle)-1. See selftest().

    `pos` advances by len(chunk) >= 1 per iteration -> guaranteed termination.
    """
    if not needle:
        raise ValueError('empty pattern')
    if chunk_size <= 0:
        raise ValueError('chunk_size must be positive')
    overlap = len(needle) - 1
    pos = 0            # bytes of the file read before the current chunk
    tail = b''         # carried overlap from the previous chunk
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                return
            buf = tail + chunk
            start = 0
            while True:
                idx = buf.find(needle, start)
                if idx < 0:
                    break
                yield pos - len(tail) + idx
                start = idx + 1
            pos += len(chunk)
            tail = buf[-overlap:] if overlap > 0 else b''


def selftest() -> None:
    """Prove the offsets match a whole-file search across chunk boundaries.

    The regression this guards: `xxxxABxxxxAB` with needle `AB` and chunk 4
    returned [3, 9] instead of [4, 10]. Small chunk sizes are the point -- a
    default 8 MiB chunk hides the bug entirely on any realistic input.
    """
    import os
    import tempfile

    cases = [
        (b'xxxxABxxxxAB', b'AB'),
        (b'ABABAB', b'AB'),
        (b'AAAAAAAA', b'AA'),
        (b'no-match-here', b'ZZ'),
        (b'AB', b'AB'),
        (b'xAB', b'AB'),
        (b'ABx', b'AB'),
        (b'', b'AB'),
        (bytes(range(256)) * 3, bytes([255, 0, 1])),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        for n, (data, needle) in enumerate(cases):
            path = os.path.join(tmp, 'case%d.bin' % n)
            with open(path, 'wb') as fh:
                fh.write(data)
            expected = []
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                expected.append(i)
                start = i + 1
            if not expected:
                continue
            # every chunk size from 1..len(data)+2 that can hold the needle
            for chunk in range(1, len(data) + 3):
                got = list(stream_search(path, needle, chunk))
                assert got == expected, (
                    'selftest FAILED: data=%r needle=%r chunk=%d -> %r, expected %r'
                    % (data[:24], needle, chunk, got, expected))
    print('selftest OK: streaming offsets match whole-file search '
          'for every chunk size 1..n+2 across %d cases' % len(cases))


def main():
    if '--selftest' in sys.argv:
        selftest()
        return
    if len(sys.argv) < 3:
        print(__doc__)
        print('  --selftest   verify offset accounting against whole-file search')
        sys.exit(1)
    path = sys.argv[1]
    needle = sys.argv[2].encode()
    chunk_mb = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    chunk = chunk_mb * 1024 * 1024

    t0 = time.time()
    hits = []
    for off in stream_search(path, needle, chunk):
        hits.append(off)
        print(f'hit at 0x{off:x}')
    dt = time.time() - t0
    size = __import__('os').path.getsize(path)
    print(f'{len(hits)} occurrence(s) of {needle!r} in {size} bytes '
          f'({dt:.1f}s, {size / max(dt, 0.001) / 1e6:.0f} MB/s)')


if __name__ == '__main__':
    main()
