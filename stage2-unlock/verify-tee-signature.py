#!/usr/bin/env python3
"""Stock-image signature and layout verifier for the trona TEE/ATF container.

What this DOES establish (from the supplied images):
  * tee.img is three wrapped components -- atf (0x13c00 @ 0), atf_dram
    (0xda00 @ 0x13e00), tee (0x2b6000 @ 0x21a00);
  * for each, the *outer* hdr[4] and the *inner* header's
    inner[0x08] + inner[0x18] are reported; in stock both are equal;
  * each inner signature occupies inner[0x13c:0x23c] (zeroed for hashing) and
    verifies RSA-2048-PSS / SHA-256 / MGF1-SHA-256 / salt 32 against the
    modulus at preloader 0x388f0, over the inner extent;
  * a walk through the outer containers ends exactly at the image extent.

What this does NOT establish:
  * whether the loader cross-checks the outer and inner lengths (that absence
    is an independent reverse-engineering finding -- see README.md and the
    disassembly of preloader 0x200f4 / 0x26034 / 0x2bc08 / 0x2ba92);
  * whether a modified outer extent would complete its transfer and preserve a
    bootable sequence;
  * anything about bootloader acceptance or unlockability.

Component offsets are fixed to the stock layout, so this is a stock-image
verifier rather than a general model of bootloader acceptance.

Exit status 0 == all performed checks passed.

Usage:
    python verify-tee-signature.py [tee.img] [preloader.img]
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TEE = os.path.join(HERE, "..", "ota-extract", "images", "tee.img")
DEFAULT_PL = os.path.join(HERE, "..", "ota-extract", "images", "preloader.img")

E = 65537
SALT_LEN = 32
HLEN = 32
KEY_OFFSET = 0x388F0
SIG_LO, SIG_HI = 0x13C, 0x23C
COMPONENTS = (("atf", 0x0), ("atf_dram", 0x13E00), ("tee", 0x21A00))


def mgf1(seed, length):
    out = b""
    for counter in range((length + HLEN - 1) // HLEN):
        out += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
    return out[:length]


def pss_verify(n, sig, data):
    """RSASSA-PSS-VERIFY, SHA-256/MGF1-SHA-256, sLen == SALT_LEN."""
    em = pow(int.from_bytes(sig, "big"), E, n).to_bytes((n.bit_length() - 1 + 7) // 8, "big")
    if em[-1] != 0xBC:
        return False
    db_len = len(em) - HLEN - 1
    masked_db, h = em[:db_len], em[db_len:db_len + HLEN]
    if masked_db[0] & 0x80:
        return False
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1(h, db_len)))
    db = bytes([db[0] & 0x7F]) + db[1:]
    pad = db_len - SALT_LEN - 1
    if db[:pad] != b"\x00" * pad or db[pad] != 0x01:
        return False
    salt = db[pad + 1:]
    return hashlib.sha256(b"\x00" * 8 + hashlib.sha256(data).digest() + salt).digest() == h


def main():
    tee_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TEE
    pl_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PL
    tee = open(tee_path, "rb").read()
    pl = open(pl_path, "rb").read()
    n = int.from_bytes(pl[KEY_OFFSET:KEY_OFFSET + 256], "big")

    last = COMPONENTS[-1][1]
    image_extent = last + 0x200 + struct.unpack_from("<I", tee, last + 4)[0]

    print("tee.img  : %s (%d bytes%s)" % (
        tee_path, len(tee),
        "" if len(tee) == image_extent else "; input is a partition dump, image extent 0x%x" % image_extent))
    print("  sha256 : %s" % hashlib.sha256(tee[:image_extent]).hexdigest())
    print("modulus  : preloader 0x%05x, %d bits" % (KEY_OFFSET, n.bit_length()))
    print()

    ok = True
    for name, outer in COMPONENTS:
        magic = struct.unpack_from("<I", tee, outer)[0]
        out_h4 = struct.unpack_from("<I", tee, outer + 4)[0]
        cname = tee[outer + 8:outer + 20].split(b"\x00")[0].decode("latin1")
        dst = struct.unpack_from("<I", tee, outer + 0x28)[0]
        mode = struct.unpack_from("<I", tee, outer + 0x2C)[0]

        ih = outer + 0x200
        inner_hdr = struct.unpack_from("<I", tee, ih + 0x08)[0]
        inner_body = struct.unpack_from("<I", tee, ih + 0x18)[0]
        extent = inner_hdr + inner_body
        resv = struct.unpack_from("<I", tee, ih + 0x23C)[0]

        data = bytearray(tee[ih:ih + extent])
        if len(data) < SIG_HI:
            print("%-9s SHORT BODY - cannot check" % name)
            ok = False
            continue
        sig = bytes(data[SIG_LO:SIG_HI])
        data[SIG_LO:SIG_HI] = b"\x00" * (SIG_HI - SIG_LO)
        verified = pss_verify(n, sig, bytes(data))

        # the next outer header follows this outer hdr[4] + its own 0x200
        nxt = outer + 0x200 + out_h4
        next_ok = (nxt == image_extent) or any(nxt == o for _, o in COMPONENTS)

        print("component %r @0x%06x  magic=0x%08x  dst=0x%08x mode=0x%x" % (cname, outer, magic, dst, mode))
        print("   copy length (outer hdr[4])      : 0x%x" % out_h4)
        print("   auth extent (inner[8]+inner[18]): 0x%x  (hdr 0x%x + body 0x%x)"
              % (extent, inner_hdr, inner_body))
        print("   reservation field inner[0x23c]  : 0x%08x%s"
              % (resv, "  (wildcard)" if resv == 0xFFFFFFFF else "  (must equal the cached size)"))
        print("   signature over inner extent     : %s" % ("PASS" if verified else "FAIL"))
        print("   next component at 0x%06x        : %s" % (nxt, "coherent" if next_ok else "INCOHERENT"))
        if not verified or not next_ok:
            ok = False
        print()
    print("RESULT: %s" % (
        "PASS - all performed checks succeeded (stock-image signature and layout "
        "verification only; this script does NOT test whether the loader "
        "cross-checks the outer and inner lengths, and makes no claim about "
        "bootloader acceptance or unlockability)"
        if ok else "FAIL - expectations not met"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
