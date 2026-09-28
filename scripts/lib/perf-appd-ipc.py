#!/usr/bin/env python3
"""Measure raw appd round trips (socket connect + hello + verb) on the installed helper.

Run as root: root is an authorized peer on the helper socket, so no product change and no
state mutation is needed. `report_registry` is read-only.

Usage: perf-appd-ipc.py [iterations]
"""

import json
import socket
import statistics
import sys
import time

SOCKET = "/run/ghostnector/appd/appd.sock"
HANDSHAKE = json.dumps({"verb": "hello", "protocol": 1}).encode()


def round_trip(verb_json: str = "", stop_after_hello: bool = False) -> float:
    began = time.perf_counter()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(SOCKET)
    try:
        sock.sendall(HANDSHAKE + b"\n")
        _ = sock.recv(65536)
        if not stop_after_hello:
            sock.sendall(verb_json.encode() + b"\n")
            _ = sock.recv(65536)
    finally:
        sock.close()
    return (time.perf_counter() - began) * 1000.0


def stats(label, values):
    values.sort()
    print(
        f"{label:30s} n={len(values):3d} p10={values[int(0.1 * (len(values) - 1))]:7.3f} "
        f"med={statistics.median(values):7.3f} p90={values[int(0.9 * (len(values) - 1))]:7.3f} ms"
    )


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    for label, verb, stop in (
        ("connect+hello", "", True),
        ("connect+hello+report_registry", '{"verb":"report_registry"}', False),
    ):
        stats(label, [round_trip(verb, stop) for _ in range(iterations)])


if __name__ == "__main__":
    main()
