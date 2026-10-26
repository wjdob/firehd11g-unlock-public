#!/usr/bin/env python3
"""MTK MT8183 preloader tool for the trona unit (Fire HD 10 / HD 10 Plus, 2021).

What it does:
  * finds the preloader's USB serial port (MediaTek 0E8D:2000) and holds it;
  * speaks two entry handshakes: the binary one (0xA0 -> 0x5F ...) and the
    READY/META one ('Y' -> "METAMETA");
  * runs a staged Download Agent probe whose whole purpose is to distinguish
    "the fuse refused the DA" from "the transfer never completed":
      - da-probe sends a body of any size, with configurable chunking and pacing,
        and reports exactly which stage produced or withheld a response;
  * if the DA is accepted, can jump to it and issue the payload block commands;
  * reads and writes single partitions (recovery, misc) from block images.

Protocol facts recovered from the PS7319 preloader image in this repository:
  * DA destination is the literal at file 0x5746: 0x40200000 (not a guess).
  * The preloader receives the body at that address, then computes a 16-bit XOR
    over the halfwords (plus the low byte when the length is odd) and sends it,
    then sends a 2-byte status. A host that sees neither is stuck before the
    checksum, which is a transfer problem rather than a refusal.
  * Commands seen in the dispatch: 0xD7 SEND_DA, 0xD5 JUMP_DA.
  * The DA is verified only when SEC_CFG bit 2 is set; otherwise the preloader
    logs "DA validation disabled on non-secure chip" and skips the verifier.

Usage:
    python stage6-lineage/mtk-tool/mtk8183.py selftest
    python stage6-lineage/mtk-tool/mtk8183.py ports
    python stage6-lineage/mtk-tool/mtk8183.py handshake --wait 30
    python stage6-lineage/mtk-tool/mtk8183.py da-probe --size 16
    python stage6-lineage/mtk-tool/mtk8183.py da-probe --size 16168 --chunk 512 --gap 0.005
    python stage6-lineage/mtk-tool/mtk8183.py da --image dumps/amonet/v11/amonet/bin/pl-payload.bin
    python stage6-lineage/mtk-tool/mtk8183.py read --lba 20544 --count 2048 --out misc.img
    python stage6-lineage/mtk-tool/mtk8183.py write --lba 20544 --image misc-clean.img

Nothing is written unless a DA has been accepted and jumped to successfully.
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time

BAUD = 115200
MTK_VID = 0x0E8D
MTK_PID_PRELOADER = 0x2000
MAGIC = 0xF00DD00D
DA_ADDR_DEFAULT = 0x40200000
BLOCK = 0x200

CMD_READ = 0x1000
CMD_WRITE = 0x1001
CMD_SWITCH = 0x1002
CMD_MAX_BLOCKS = 0x1005
CMD_RPMB_READ = 0x2000
CMD_RPMB_WRITE = 0x2001
CMD_REBOOT = 0x3000
CMD_MEM_READ = 0x5000

HELLO = b"\xb1\xb2\xb3\xb4"


class DeviceLost(Exception):
    """The serial device disappeared mid-session (usually a watchdog reset)."""


def log(msg: str) -> None:
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #
class Transport:
    """Minimal byte transport. Real one wraps pyserial; the selftest mocks it."""

    def __init__(self, port: str, baud: int = BAUD, timeout: float = 0.5):
        import serial  # imported late so selftest runs without a port

        self._dev = serial.Serial(port, baud, timeout=timeout, write_timeout=2.0)
        try:
            self._dev.set_buffer_size(rx_size=65536, tx_size=65536)
        except Exception:
            pass
        self.port = port

    def read(self, n: int, timeout: float | None = None) -> bytes:
        # Never reprogram the port timeout mid-session: on Windows that reconfigures the
        # device and raises as soon as the boot loop has already taken it away. Poll
        # in_waiting instead, which is a plain ioctl and fails cleanly.
        if timeout is None:
            return self._dev.read(n)
        deadline = time.time() + timeout
        buf = b""
        while len(buf) < n and time.time() < deadline:
            avail = self.in_waiting
            if avail:
                chunk = self._dev.read(min(avail, n - len(buf)))
                if not chunk:
                    break
                buf += chunk
            else:
                time.sleep(0.003)
        return buf

    def write(self, data: bytes) -> int:
        return self._dev.write(data)

    def reset_input(self) -> None:
        try:
            self._dev.reset_input_buffer()
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._dev.close()
        except Exception:
            pass

    @property
    def in_waiting(self) -> int:
        try:
            return self._dev.in_waiting
        except Exception:
            return 0


def list_ports() -> list[tuple[str, str, int | None, int | None]]:
    from serial.tools import list_ports as lp

    out = []
    for p in lp.comports():
        out.append((p.device, p.description or "", p.vid, p.pid))
    return out


def find_preloader(wait_s: float = 0.0) -> str | None:
    """Return the first MediaTek 0E8D:2000 port, optionally waiting for one."""
    deadline = time.time() + wait_s
    while True:
        for device, desc, vid, pid in list_ports():
            if vid == MTK_VID and pid == MTK_PID_PRELOADER:
                return device
        if time.time() >= deadline:
            return None
        time.sleep(0.05)


# --------------------------------------------------------------------------- #
# preloader protocol
# --------------------------------------------------------------------------- #
class Result:
    def __init__(self) -> None:
        self.stage = "new"
        self.ok = False
        self.detail: list[str] = []
        self.header_status: bytes | None = None
        self.checksum: bytes | None = None
        self.body_status: bytes | None = None

    def note(self, msg: str) -> None:
        self.detail.append(msg)
        log("  " + msg)

    def fail(self, stage: str, msg: str) -> "Result":
        self.stage = stage
        self.note(msg)
        return self

    def done(self, stage: str, msg: str) -> "Result":
        self.stage = stage
        self.ok = True
        self.note(msg)
        return self


class Preloader:
    def __init__(self, tr: Transport):
        self.tr = tr

    # ---- handshakes ----
    def wait_ready(self, timeout: float = 5.0) -> bool:
        """Wait for the 'READY' banner the preloader emits in META-wait."""
        deadline = time.time() + timeout
        seen = b""
        while time.time() < deadline:
            b = self.tr.read(1, timeout=0.2)
            if not b:
                continue
            seen += b
            if seen.endswith(b"READY"):
                log("  READY banner seen")
                return True
            if len(seen) > 64:
                seen = seen[-16:]
        return False

    def send_meta(self, cmd: bytes = b"METAMETA", timeout: float = 5.0) -> bool:
        """The READY handshake: wait for 'Y', then send the mode command."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            b = self.tr.read(1, timeout=0.2)
            if b == b"Y":
                self.tr.write(cmd)
                log("  sent %r after 'Y'" % cmd)
                return True
        return False

    def handshake_binary(self, tries: int = 40) -> bool:
        for i in range(tries):
            self.tr.write(b"\xa0")
            if self.tr.read(1, timeout=0.2) == b"\x5f":
                for tx, want in ((b"\x0a", b"\xf5"), (b"\x50", b"\xaf"), (b"\x05", b"\xfa")):
                    self.tr.write(tx)
                    if self.tr.read(1, timeout=0.5) != want:
                        return False
                return True
        return False

    # ---- primitives ----
    def _echo(self, value: int | bytes, size: int = 4) -> bool:
        data = value if isinstance(value, bytes) else value.to_bytes(size, "big")
        self.tr.write(data)
        got = self.tr.read(len(data), timeout=1.0)
        return got == data

    def _status(self, timeout: float = 2.0) -> bytes | None:
        try:
            b = self.tr.read(2, timeout=timeout)
        except Exception as exc:
            raise DeviceLost(str(exc)) from exc
        return b if len(b) == 2 else None

    # ---- SEND_DA ----
    def send_da(self, data: bytes, addr: int = DA_ADDR_DEFAULT,
                chunk: int = 0, gap: float = 0.0,
                settle: float = 0.02) -> Result:
        """Send a DA body. chunk=0 sends it in one write.

        Stages reported: 'header-echo', 'header-status', 'body', 'checksum',
        'body-status'. A missing response names the stage that stalled, which is
        what separates a refusal from an incomplete transfer.
        """
        r = Result()
        if not self._echo(0xD7, 1):
            return r.fail("header-echo", "0xD7 not echoed")
        if not self._echo(addr, 4):
            return r.fail("header-echo", "address not echoed")
        if not self._echo(len(data), 4):
            return r.fail("header-echo", "length not echoed")
        if not self._echo(0, 4):
            return r.fail("header-echo", "sig_len not echoed")
        r.header_status = self._status()
        if r.header_status is None:
            return r.fail("header-status", "no status after the header")
        if r.header_status != b"\x00\x00":
            return r.fail("header-status", "header refused: %s" % r.header_status.hex())
        r.note("header accepted")
        if settle:
            time.sleep(settle)

        sent = 0
        t0 = time.time()
        if chunk <= 0:
            self.tr.write(data)
            sent = len(data)
        else:
            for off in range(0, len(data), chunk):
                self.tr.write(data[off:off + chunk])
                sent += min(chunk, len(data) - off)
                if gap:
                    time.sleep(gap)
        r.note("body sent: %d bytes in %.3fs" % (sent, time.time() - t0))

        try:
            r.checksum = self._status(timeout=3.0)
        except DeviceLost as exc:
            return r.fail("device-lost", "port vanished after the body: %s" % exc)
        if r.checksum is None:
            return r.fail("checksum", "no checksum after the body (preloader did not finish receiving)")
        r.note("checksum %s" % r.checksum.hex())
        r.body_status = self._status(timeout=3.0)
        if r.body_status is None:
            return r.fail("body-status", "no status after the checksum")
        r.note("body status %s" % r.body_status.hex())
        if r.body_status != b"\x00\x00":
            return r.fail("body-status", "DA refused by the preloader (verifier)")
        return r.done("accepted", "DA accepted")

    def jump_da(self, addr: int = DA_ADDR_DEFAULT, timeout: float = 3.0) -> Result:
        r = Result()
        if not self._echo(0xD5, 1):
            return r.fail("jump-echo", "0xD5 not echoed")
        if not self._echo(addr, 4):
            return r.fail("jump-echo", "address not echoed")
        st = self._status()
        if st is None:
            return r.fail("jump-status", "no status")
        if st != b"\x00\x00":
            return r.fail("jump-status", "jump refused: %s" % st.hex())
        hello = self.tr.read(4, timeout=timeout)
        if hello != HELLO:
            return r.fail("hello", "bad payload hello %r" % hello)
        return r.done("hello", "payload is running")

    # ---- payload commands ----
    def _cmd(self, cmd: int, *args: int) -> None:
        self.tr.write(struct.pack(">II", MAGIC, cmd) + b"".join(struct.pack(">I", a) for a in args))

    def max_blocks(self) -> int:
        self._cmd(CMD_MAX_BLOCKS)
        return struct.unpack(">I", self._read_exact(4, 3.0))[0]

    def _read_exact(self, n: int, timeout: float) -> bytes:
        try:
            out = self.tr.read(n, timeout=timeout)
        except Exception as exc:
            raise DeviceLost(str(exc)) from exc
        if len(out) != n:
            raise TimeoutError("short read %d/%d" % (len(out), n))
        return out

    def switch(self, part: int) -> None:
        self._cmd(CMD_SWITCH, part)

    def read_block(self, lba: int, timeout: float = 3.0) -> bytes:
        self._cmd(CMD_READ, lba)
        return self._read_exact(BLOCK, timeout)

    def write_block(self, lba: int, data: bytes, timeout: float = 3.0) -> None:
        if len(data) != BLOCK:
            raise ValueError("block must be 0x200 bytes")
        self._cmd(CMD_WRITE, lba)
        self.tr.write(data)
        ack = self._read_exact(4, timeout)
        if ack != b"\xd0\xd0\xd0\xd0":
            raise RuntimeError("write not acknowledged: %r" % ack)

    def reboot(self) -> None:
        self._cmd(CMD_REBOOT)


# --------------------------------------------------------------------------- #
# offline selftest: a mock preloader that follows the recovered protocol
# --------------------------------------------------------------------------- #
def selftest() -> int:
    """Exercise the framing and checksum path against a scripted device.

    The mock is deliberately simple: it answers the handshake, the DA header,
    the body, the checksum and the status, then the jump and one block read.
    This validates the host side only; it says nothing about a real preloader.
    """
    class Scripted:
        """Byte-level mock of the recovered preloader protocol."""

        def __init__(self) -> None:
            self.rx = b""
            self.out = b""
            self.state = "hs:a0"
            self.hdr = b""
            self.cmd = b""
            self.body_len = 0
            self.blocks = {7: b"\xab" * BLOCK}

        def write(self, data: bytes) -> int:
            self.rx += data
            self._pump()
            return len(data)

        def _pump(self) -> None:
            while True:
                if self.state.startswith("hs:"):
                    want = {"hs:a0": b"\xa0", "hs:0a": b"\x0a", "hs:50": b"\x50", "hs:05": b"\x05"}[self.state]
                    reply = {b"\xa0": b"\x5f", b"\x0a": b"\xf5", b"\x50": b"\xaf", b"\x05": b"\xfa"}[want]
                    if not self.rx:
                        return
                    if self.rx[:1] != want:
                        raise AssertionError("mock: expected %r got %r" % (want, self.rx[:1]))
                    self.rx = self.rx[1:]
                    self.out += reply
                    self.state = {b"\xa0": "hs:0a", b"\x0a": "hs:50", b"\x50": "hs:05", b"\x05": "cmd"}[want]
                    continue
                if self.state == "cmd":
                    if not self.rx:
                        return
                    self.cmd, self.rx = self.rx[:1], self.rx[1:]
                    self.out += self.cmd      # the preloader echoes the command byte
                    self.hdr = b""
                    self.state = "hdr"
                    continue
                if self.state == "hdr":
                    need = 12 if self.cmd == b"\xd7" else 4
                    while self.rx and len(self.hdr) < need:
                        self.out += self.rx[:1]
                        self.hdr += self.rx[:1]
                        self.rx = self.rx[1:]
                    if len(self.hdr) < need:
                        return
                    self.out += b"\x00\x00"
                    if self.cmd == b"\xd7":
                        self.body_len = int.from_bytes(self.hdr[4:8], "big")
                        self.state = "body"
                    else:
                        self.out += b"\xb1\xb2\xb3\xb4"
                        self.state = "payload"
                    continue
                if self.state == "body":
                    if len(self.rx) < self.body_len:
                        return
                    self.rx = self.rx[self.body_len:]
                    self.out += b"\x12\x34" + b"\x00\x00"
                    self.state = "cmd"
                    continue
                if self.state == "payload":
                    if len(self.rx) < 8:
                        return
                    magic, cmd = struct.unpack(">II", self.rx[:8])
                    assert magic == MAGIC
                    if cmd == CMD_MAX_BLOCKS:
                        self.rx = self.rx[8:]
                        self.out += struct.pack(">I", 64)
                        continue
                    if cmd == CMD_READ:
                        if len(self.rx) < 12:
                            return
                        lba = struct.unpack(">I", self.rx[8:12])[0]
                        self.rx = self.rx[12:]
                        self.out += self.blocks.get(lba, b"\x00" * BLOCK)
                        continue
                    return
                return

        def read(self, n: int, timeout: float | None = None) -> bytes:
            b, self.out = self.out[:n], self.out[n:]
            return b

        def reset_input(self) -> None:
            self.rx = b""

        @property
        def in_waiting(self) -> int:
            return len(self.out)

    tr = Scripted()
    pl = Preloader(tr)  # type: ignore[arg-type]
    ok = True
    ok &= pl.handshake_binary()
    log("selftest: handshake %s" % ("ok" if ok else "FAILED"))
    r = pl.send_da(b"\x00" * 64, addr=DA_ADDR_DEFAULT, settle=0)
    ok &= r.ok
    log("selftest: da %s (%s)" % ("ok" if r.ok else "FAILED", r.stage))
    j = pl.jump_da()
    ok &= j.ok
    log("selftest: jump %s (%s)" % ("ok" if j.ok else "FAILED", j.stage))
    blk = pl.read_block(7)
    ok &= blk == b"\xab" * BLOCK
    log("selftest: block read %s" % ("ok" if ok else "FAILED"))
    log("selftest: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def open_pl(args) -> tuple[Transport, Preloader]:
    """Open the preloader, retrying while the boot loop keeps recycling it.

    Detection and open are separate steps: a window can close between them, so a
    failed open is retried until the wait budget expires rather than being fatal.
    """
    deadline = time.time() + max(args.wait, 0) + (5.0 if args.port else 0.0)
    last = None
    while True:
        port = args.port or find_preloader(wait_s=0)
        if port:
            try:
                tr = Transport(port, timeout=args.timeout)
                log("port %s" % port)
                return tr, Preloader(tr)
            except Exception as exc:
                last = exc
        if time.time() >= deadline:
            raise SystemExit("no usable preloader port (last error: %s)" % last)
        time.sleep(0.02)


def cmd_ports(_args) -> int:
    rows = list_ports()
    if not rows:
        print("no serial ports")
        return 1
    for device, desc, vid, pid in rows:
        mark = " <- preloader" if vid == MTK_VID and pid == MTK_PID_PRELOADER else ""
        print("%-8s %04X:%04X  %s%s" % (device, vid or 0, pid or 0, desc, mark))
    return 0


def cmd_handshake(args) -> int:
    tr, pl = open_pl(args)
    try:
        ready = pl.wait_ready(timeout=2.0)
        log("READY banner: %s" % ("yes" if ready else "no"))
        ok = pl.handshake_binary()
        log("binary handshake: %s" % ("OK" if ok else "no"))
        return 0 if ok else 2
    finally:
        tr.close()


def cmd_da_probe(args) -> int:
    tr, pl = open_pl(args)
    try:
        if not pl.handshake_binary():
            log("handshake failed")
            return 2
        body = b"\x00" * args.size
        r = pl.send_da(body, addr=args.addr, chunk=args.chunk, gap=args.gap, settle=args.settle)
        log("result: stage=%s ok=%s" % (r.stage, r.ok))
        if r.stage == "device-lost":
            log("diagnosis: the preloader disappeared immediately after the body, which is")
            log("           what a reset looks like. A 16-byte body cannot fail on transfer,")
            log("           so this is either the secure verifier dead-looping or a crash.")
            log("           Re-run with a larger body to compare; a small body that vanishes")
            log("           means the gate, not the transport.")
        elif r.stage == "checksum":
            log("diagnosis: the preloader stopped before the checksum, so the body transfer")
            log("           did not complete. Try --chunk 512 --gap 0.005, or a smaller --size.")
        elif r.stage == "body-status" and not r.ok:
            log("diagnosis: the preloader answered the checksum and refused the DA, which is")
            log("           the secure verifier path (SEC_CFG bit 2 set).")
        return 0 if r.ok else 3
    finally:
        tr.close()


def cmd_da(args) -> int:
    with open(args.image, "rb") as fh:
        body = fh.read()
    tr, pl = open_pl(args)
    try:
        if not pl.handshake_binary():
            log("handshake failed")
            return 2
        r = pl.send_da(body, addr=args.addr, chunk=args.chunk, gap=args.gap, settle=args.settle)
        if not r.ok:
            log("DA not accepted (stage %s); nothing written" % r.stage)
            return 3
        j = pl.jump_da(addr=args.addr)
        if not j.ok:
            log("jump failed (%s); nothing written" % j.stage)
            return 4
        log("payload live, max_blocks=%d" % pl.max_blocks())
        log("use read/write subcommands on the same session for block access")
        return 0
    finally:
        tr.close()


def cmd_read(args) -> int:
    tr, pl = open_pl(args)
    try:
        if not pl.handshake_binary():
            return 2
        with open(args.image, "rb") as fh:
            body = fh.read()
        r = pl.send_da(body, addr=args.addr, chunk=args.chunk, gap=args.gap)
        if not r.ok or not pl.jump_da(addr=args.addr).ok:
            log("DA not live; aborting read")
            return 3
        pl.switch(args.part)
        out = bytearray()
        for i in range(args.count):
            out += pl.read_block(args.lba + i)
            if i % 256 == 0:
                log("read %d/%d" % (i, args.count))
        with open(args.out, "wb") as fh:
            fh.write(out)
        log("wrote %s (%d bytes)" % (args.out, len(out)))
        return 0
    finally:
        tr.close()


def cmd_write(args) -> int:
    if not args.yes:
        raise SystemExit("refusing to write without --yes")
    with open(args.image, "rb") as fh:
        img = fh.read()
    if len(img) != args.count * BLOCK:
        raise SystemExit("image size %d does not match %d blocks" % (len(img), args.count))
    tr, pl = open_pl(args)
    try:
        if not pl.handshake_binary():
            return 2
        with open(args.da, "rb") as fh:
            body = fh.read()
        r = pl.send_da(body, addr=args.addr, chunk=args.chunk, gap=args.gap)
        if not r.ok or not pl.jump_da(addr=args.addr).ok:
            log("DA not live; aborting write")
            return 3
        pl.switch(args.part)
        for i in range(args.count):
            pl.write_block(args.lba + i, img[i * BLOCK:(i + 1) * BLOCK])
            if i % 64 == 0:
                log("wrote %d/%d" % (i, args.count))
        log("wrote %d blocks at lba %d" % (args.count, args.lba))
        return 0
    finally:
        tr.close()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", help="serial port, default: auto-detect 0E8D:2000")
    p.add_argument("--wait", type=float, default=0.0, help="seconds to wait for the port")
    p.add_argument("--timeout", type=float, default=0.5, help="base read timeout")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest").set_defaults(func=lambda a: selftest())
    sub.add_parser("ports").set_defaults(func=cmd_ports)

    h = sub.add_parser("handshake")
    h.set_defaults(func=cmd_handshake)

    def da_args(sp):
        sp.add_argument("--addr", type=lambda x: int(x, 0), default=DA_ADDR_DEFAULT)
        sp.add_argument("--chunk", type=int, default=0)
        sp.add_argument("--gap", type=float, default=0.0)
        sp.add_argument("--settle", type=float, default=0.02)

    d = sub.add_parser("da-probe", help="send a zero body and report which stage stalled")
    d.add_argument("--size", type=int, default=16)
    da_args(d)
    d.set_defaults(func=cmd_da_probe)

    d2 = sub.add_parser("da", help="send and jump to a DA image")
    d2.add_argument("--image", required=True)
    da_args(d2)
    d2.set_defaults(func=cmd_da)

    r = sub.add_parser("read", help="read blocks through the DA payload")
    r.add_argument("--image", default=r"dumps\amonet\v11\amonet\bin\pl-payload.bin")
    r.add_argument("--lba", type=int, required=True)
    r.add_argument("--count", type=int, required=True)
    r.add_argument("--part", type=int, default=0)
    r.add_argument("--out", required=True)
    da_args(r)
    r.set_defaults(func=cmd_read)

    w = sub.add_parser("write", help="write blocks through the DA payload")
    w.add_argument("--da", default=r"dumps\amonet\v11\amonet\bin\pl-payload.bin")
    w.add_argument("--lba", type=int, required=True)
    w.add_argument("--count", type=int, required=True)
    w.add_argument("--part", type=int, default=0)
    w.add_argument("--image", required=True)
    w.add_argument("--yes", action="store_true")
    da_args(w)
    w.set_defaults(func=cmd_write)
    return p


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
