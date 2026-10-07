#!/usr/bin/env python3
"""Send Fire OS 7.3.3.1's five-argument WebView-Zygote preload request."""

import argparse
import socket
import struct


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError(f"EOF after {length - remaining} of {length} response bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=43212)
    parser.add_argument("--package", required=True)
    parser.add_argument("--libs", required=True)
    parser.add_argument("--library", required=True)
    parser.add_argument("--cache-key", required=True)
    args = parser.parse_args()

    fields = [
        "5",
        "--preload-package",
        args.package,
        args.libs,
        args.library,
        args.cache_key,
    ]
    wire = ("\n".join(fields) + "\n").encode("utf-8")
    if any(b"\n" in value.encode("utf-8") for value in fields):
        raise ValueError("preload fields cannot contain newlines")

    with socket.create_connection((args.host, args.port), timeout=10.0) as sock:
        sock.settimeout(30.0)
        sock.sendall(wire)
        response = struct.unpack(">i", recv_exact(sock, 4))[0]

    # Hosted PS7331.4463N WebViewZygoteInit writes 1 for a successful
    # preloadInZygote() return and 0 for failure. The exact 4460N tablet has
    # already accepted this command family; preserve the raw value as evidence.
    print(f"preload_response={response}")
    if response != 1:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
