#!/usr/bin/env python3
"""Offline check of the trona LK container signature boundary.

Reproduces the facts the preloader enforces before it authenticates LK
(see README.md, "Container-header audit"):

  * the verifying key is the *image* key at preloader 0x37b98 -- NOT the
    unlock key at 0x37c98 and NOT the alternate image key at 0x37a98;
  * the signature is the last 0x100 bytes of the LK image;
  * the signed bytes are exactly LK[0x200 : hdr.size), where hdr.size is
    the dword at container-header offset 4 -- i.e. the leading 0x200-byte
    BRLYT header is outside the signature;
  * hdr.size is also the value the preloader uses as the load length and
    as the verify length (0x19d2e loads, 0x19d62 verifies).

RSA-PSS (SHA-256 / MGF1-SHA-256 / salt 32) is implemented here so the check
needs no third-party module; if `cryptography` is installed it is used as a
cross-check.

Usage:
    python verify-lk-signature.py [lk.img] [preloader.img]

Defaults point at the OTA-extracted images.  Exit status 0 == all checks pass.
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LK = os.path.join(HERE, "..", "ota-extract", "images", "lk.img")
DEFAULT_PL = os.path.join(HERE, "..", "ota-extract", "images", "preloader.img")
# preloader key block: three consecutive 256-byte RSA-2048 moduli
KEY_OFFSETS = {
    "image-verify alternate 0x37a98": (0x37A98, False),
    "image-verify (prod)    0x37b98": (0x37B98, True),
    "unlock                 0x37c98": (0x37C98, False),
}
E = 65537
SALT_LEN = 32
HLEN = 32


def mgf1(seed, length):
    out = b""
    for counter in range((length + HLEN - 1) // HLEN):
        out += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
    return out[:length]


def pss_verify(n, sig, data):
    """RSASSA-PSS-VERIFY with SHA-256, MGF1-SHA-256, sLen == SALT_LEN."""
    mod_bits = n.bit_length()
    em_len = (mod_bits - 1 + 7) // 8
    em = pow(int.from_bytes(sig, "big"), E, n).to_bytes(em_len, "big")
    if em[-1] != 0xBC:                          # RFC 8017 PSS trailer
        return False
    db_len = em_len - HLEN - 1
    masked_db, h = em[:db_len], em[db_len:db_len + HLEN]
    if masked_db[0] & 0x80:                     # leftmost 8*emLen-emBits bits
        return False
    db = bytes(a ^ b for a, b in zip(masked_db, mgf1(h, db_len)))
    db = bytes([db[0] & 0x7F]) + db[1:]
    pad_len = db_len - SALT_LEN - 1
    if db[:pad_len] != b"\x00" * pad_len or db[pad_len] != 0x01:
        return False
    salt = db[pad_len + 1:]
    return hashlib.sha256(b"\x00" * 8 + hashlib.sha256(data).digest() + salt).digest() == h


def cryptography_crosscheck(n, sig, data):
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        return None
    try:
        rsa.RSAPublicNumbers(E, n).public_key().verify(
            sig, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=SALT_LEN),
            hashes.SHA256())
        return True
    except Exception:
        return False


def main():
    lk_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LK
    pl_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PL
    lk = open(lk_path, "rb").read()
    pl = open(pl_path, "rb").read()

    size = struct.unpack_from("<I", lk, 4)[0]          # container header -> size
    magic = struct.unpack_from("<I", lk, 0)[0]
    name = lk[8:20].split(b"\x00")[0].decode("latin1")

    # A raw partition dump is longer than the image; the container header says
    # where the image ends (payload size + 0x200 header).
    img_len = size + 0x200
    if len(lk) > img_len:
        print("note: input is longer than the image (partition dump?) - "
              "using hdr.size+0x200 = 0x%x as the image extent" % img_len)
    else:
        img_len = len(lk)
    sig = lk[img_len - 0x100:img_len]
    print("LK image   : %s (%d bytes, image extent 0x%x)" % (lk_path, len(lk), img_len))
    print("  magic    : 0x%08x   name: %r   hdr.size: 0x%x" % (magic, name, size))
    print("  hdr.size + 0x200 == image extent: %s" % (size + 0x200 == img_len))
    print("  _LK_VER: tag at 0x%x (expected 0x%x)"
          % (lk.find(b"_LK_VER:"), img_len - 0x10A))
    print()

    signed = lk[0x200:img_len - 0x100]     # payload minus trailing signature
    unsigned = lk[0:img_len - 0x100]       # what including the header would mean
    print("signature : last 0x100 bytes of the image")
    print("signed    : LK[0x200:%d)  (%d bytes)" % (img_len - 0x100, len(signed)))
    print()

    ok = True
    for label, (off, expect_pass) in KEY_OFFSETS.items():
        n = int.from_bytes(pl[off:off + 256], "big")
        v_hdr = pss_verify(n, sig, unsigned)
        v_pay = pss_verify(n, sig, signed)
        x = cryptography_crosscheck(n, sig, signed)
        print("preloader key %s  (n[0:4]=%s)"
              % (label, pl[off:off + 4].hex()))
        print("    over LK[0x000:...-0x100) : %s" % ("VERIFIES" if v_hdr else "rejected"))
        print("    over LK[0x200:...-0x100) : %s%s"
              % ("VERIFIES" if v_pay else "rejected",
                 "" if x is None else "   (cryptography cross-check: %s)"
                 % ("VERIFIES" if x else "rejected")))
        if v_pay != expect_pass or (expect_pass and v_hdr):
            ok = False
    print()
    print("RESULT: %s" % ("PASS - the 0x200-byte container header is outside the "
                          "signature; the prod image key verifies LK[0x200:-0x100)"
                          if ok else "FAIL - expectations not met"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
