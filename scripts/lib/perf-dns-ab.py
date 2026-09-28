#!/usr/bin/env python3
"""Focused DNS A/B: through a relay vs straight to the upstream.

Usage:
  perf-dns-ab.py --direct HOST:PORT --via HOST:PORT [--name example.com] [--n 300]

Alternates direct and via in one process and reports p10/median/p90 and the paired
difference. Used to isolate the chokepoint's own relay cost from Tor's DNS cost.
"""

import argparse
import random
import socket
import statistics
import struct
import sys
import time

DNS_ID = 0x4748


def build_query(name):
    q = struct.pack("!HHHHHH", DNS_ID, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return q


def query(server, payload, timeout=8.0):
    host, port = server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    began = time.perf_counter()
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - began) * 1000.0
        if len(data) < 12:
            raise RuntimeError("short answer")
        return elapsed
    finally:
        sock.close()


def address(value):
    host, _, port = value.rpartition(":")
    return host, int(port)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--direct", required=True)
    parser.add_argument("--via", required=True)
    parser.add_argument("--name", default="example.com")
    parser.add_argument("--n", type=int, default=300)
    args = parser.parse_args()

    direct = address(args.direct)
    via = address(args.via)
    payload = build_query(args.name)
    for _ in range(10):
        query(direct, payload)
        query(via, payload)

    direct_times, via_times, differences = [], [], []
    order = [True, False]
    for _ in range(args.n):
        random.shuffle(order)
        results = {}
        for use_via in order:
            server = via if use_via else direct
            try:
                results[use_via] = query(server, payload)
            except Exception:  # noqa: BLE001
                results[use_via] = None
        if results.get(True) is not None:
            via_times.append(results[True])
        if results.get(False) is not None:
            direct_times.append(results[False])
        if results.get(True) is not None and results.get(False) is not None:
            differences.append(results[True] - results[False])

    def report(label, values):
        if not values:
            print(f"{label}: no samples")
            return
        ordered = sorted(values)
        print(
            f"{label}: n={len(values)} p10={ordered[int(0.1*(len(ordered)-1))]:8.3f}ms "
            f"med={statistics.median(values):8.3f}ms p90={ordered[int(0.9*(len(ordered)-1))]:8.3f}ms"
        )

    report("direct", direct_times)
    report("via   ", via_times)
    if differences:
        ordered = sorted(differences)
        print(
            f"paired via-direct: n={len(differences)} "
            f"p10={ordered[int(0.1*(len(ordered)-1))]:8.3f}ms "
            f"med={statistics.median(differences):8.3f}ms "
            f"p90={ordered[int(0.9*(len(ordered)-1))]:8.3f}ms "
            f"mean={statistics.mean(differences):8.3f}ms"
        )


if __name__ == "__main__":
    sys.exit(main())
