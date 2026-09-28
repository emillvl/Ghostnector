#!/usr/bin/env python3
"""One DNS query, timed, printed as CSV. Used to alternate users/paths per query.

Usage: perf-dns-once.py --resolver HOST:PORT --name NAME [--iter N] [--tag LABEL]
Prints: iter,user,resolver,ms
"""

import argparse
import getpass
import socket
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver", required=True)
    parser.add_argument("--name", default="checkip.amazonaws.com")
    parser.add_argument("--iter", type=int, default=0)
    parser.add_argument("--tag", default="")
    parser.add_argument("--timeout", type=float, default=8.0)
    args = parser.parse_args()

    host, _, port = args.resolver.rpartition(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(args.timeout)
    began = time.perf_counter()
    try:
        sock.sendto(build_query(args.name), (host, int(port)))
        sock.recvfrom(4096)
        elapsed = (time.perf_counter() - began) * 1000.0
        print(f"{args.iter},{getpass.getuser()},{args.resolver},{elapsed:.3f},{args.tag}")
    except Exception as error:  # noqa: BLE001
        print(f"{args.iter},{getpass.getuser()},{args.resolver},timeout,{args.tag}:{error}"[:160])
    finally:
        sock.close()


if __name__ == "__main__":
    sys.exit(main())
