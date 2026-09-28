#!/usr/bin/env python3
"""APP-scope HTTP latency: the D-50 relay path vs direct SOCKS, same Tor instance.

Runs INSIDE a protected APP namespace (launched through `ghostnector run`). Each iteration
resolves the name through the namespace's own chokepoint (its /etc/resolv.conf points at
10.200.0.1:53), then measures both routes to the same resolved address, interleaved:

  relay   ordinary TCP to the destination: the namespace DNAT sends it to the relay, which
          reads SO_ORIGINAL_DST and speaks SOCKS to the core's SocksPort.
  socks   SOCKS5 CONNECT straight to 10.200.0.1:9050 (the namespace policy deliberately
          allows this), the same Tor, no relay hop.

Prints one CSV line per sample on stdout (the session relays it to the caller's file):

  iter,epoch,route,ok,dns_ms,connect_ms,socks_ms,ttfb_ms,body_ms,total_ms,bytes,exit_ip,note
"""

import argparse
import random
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


def skip_name(data, offset):
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def resolve(name, resolver, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        began = time.perf_counter()
        sock.sendto(build_query(name), resolver)
        data, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - began) * 1000.0
        ident, flags, qd, an = struct.unpack("!HHHH", data[:8])
        if ident != DNS_ID or flags & 0xF:
            raise RuntimeError("bad DNS answer")
        offset = 12
        for _ in range(qd):
            offset = skip_name(data, offset) + 4
        for _ in range(an):
            offset = skip_name(data, offset)
            kind, cls, _ttl, length = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10
            if kind == 1 and cls == 1 and length == 4:
                return socket.inet_ntoa(data[offset : offset + 4]), elapsed
            offset += length
        raise RuntimeError("no A record")
    finally:
        sock.close()


def read_response(sock, first_byte_at):
    chunk = sock.recv(65536)
    if not chunk:
        raise RuntimeError("empty response")
    ttfb = (time.perf_counter() - first_byte_at) * 1000.0
    began = time.perf_counter()
    body = chunk
    while True:
        piece = sock.recv(65536)
        if not piece:
            break
        body += piece
    body_ms = (time.perf_counter() - began) * 1000.0
    text = body.decode("latin-1", "replace")
    status_line = text.split("\r\n", 1)[0]
    separator = body.find(b"\r\n\r\n")
    payload = body[separator + 4 :] if separator >= 0 else b""
    exit_ip = ""
    for token in payload.decode("latin-1", "replace").split():
        parts = token.split(".")
        if len(parts) == 4 and all(part.isdigit() and int(part) < 256 for part in parts):
            exit_ip = token
            break
    return {
        "status_ok": " 200" in status_line,
        "status_line": status_line,
        "exit_ip": exit_ip,
        "ttfb_ms": ttfb,
        "body_ms": body_ms,
        "bytes": len(body),
    }


def http_get(sock, host, path):
    request = (
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
        "Connection: close\r\nUser-Agent: gh-perf-app\r\n\r\n"
    )
    began = time.perf_counter()
    sock.sendall(request.encode())
    return read_response(sock, began)


def socks_connect(proxy, address, port):
    """SOCKS5 no-auth CONNECT to an IPv4 destination; returns (socket, handshake_ms)."""
    sock = socket.create_connection(proxy, timeout=15)
    sock.settimeout(15)
    began = time.perf_counter()
    sock.sendall(b"\x05\x01\x00")
    choice = sock.recv(2)
    if len(choice) != 2 or choice[0] != 5 or choice[1] != 0:
        raise RuntimeError(f"SOCKS method refused: {choice!r}")
    request = b"\x05\x01\x00\x01" + socket.inet_aton(address) + struct.pack("!H", port)
    sock.sendall(request)
    head = sock.recv(4)
    if len(head) != 4 or head[0] != 5 or head[1] != 0:
        raise RuntimeError(f"SOCKS refused: {head!r}")
    if head[3] == 1:
        sock.recv(6)
    elif head[3] == 4:
        sock.recv(18)
    else:
        length = sock.recv(1)[0]
        sock.recv(length + 2)
    return sock, (time.perf_counter() - began) * 1000.0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--host", default="checkip.amazonaws.com")
    parser.add_argument("--http-path", default="/")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--resolver", default="10.200.0.1:53")
    parser.add_argument("--socks", default="10.200.0.1:9050")
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()
    resolver_host, _, resolver_port = args.resolver.partition(":")
    socks_host, _, socks_port = args.socks.partition(":")
    resolver = (resolver_host, int(resolver_port))
    proxy = (socks_host, int(socks_port))

    def emit(row):
        fields = [
            str(row.get("iter", 0)),
            f"{time.time():.3f}",
            row.get("route", ""),
            str(row.get("ok", 0)),
            row.get("dns_ms", ""),
            row.get("connect_ms", ""),
            row.get("socks_ms", ""),
            row.get("ttfb_ms", ""),
            row.get("body_ms", ""),
            f"{row.get('total_ms', 0):.2f}",
            str(row.get("bytes", 0)),
            row.get("exit_ip", ""),
            str(row.get("note", "")).replace(",", ";"),
        ]
        print(",".join(str(value) for value in fields), flush=True)

    for iteration in range(1, args.iterations + 1):
        route_order = ["relay", "socks"]
        random.shuffle(route_order)
        address = None
        dns_ms = None
        try:
            address, dns_ms = resolve(args.host, resolver, args.timeout)
        except Exception as error:  # noqa: BLE001
            emit({"iter": iteration, "note": f"dns:{type(error).__name__}:{error}"})
            continue
        for route in route_order:
            began = time.perf_counter()
            row = {"iter": iteration, "route": route, "dns_ms": f"{dns_ms:.2f}"}
            try:
                if route == "socks":
                    sock, socks_ms = socks_connect(proxy, address, args.port)
                    row["connect_ms"] = ""
                    row["socks_ms"] = f"{socks_ms:.2f}"
                    row["ttfb_start"] = time.perf_counter()
                    result = http_get(sock, args.host, args.http_path)
                    sock.close()
                else:
                    connect_began = time.perf_counter()
                    sock = socket.create_connection((address, args.port), timeout=args.timeout)
                    row["connect_ms"] = f"{(time.perf_counter() - connect_began) * 1000.0:.2f}"
                    row["socks_ms"] = ""
                    result = http_get(sock, args.host, args.http_path)
                    sock.close()
                row.update({key: value for key, value in result.items() if key not in ("status_line",)})
                row["ok"] = 1 if result["status_ok"] else 0
                if not result["status_ok"]:
                    row["note"] = f"http:{result['status_line']}"
            except Exception as error:  # noqa: BLE001
                row["ok"] = 0
                row["note"] = f"{route}:{type(error).__name__}:{error}"
            for key in ("ttfb_ms", "body_ms"):
                if isinstance(row.get(key), float):
                    row[key] = f"{row[key]:.2f}"
            row["total_ms"] = (time.perf_counter() - began) * 1000.0
            emit(row)


if __name__ == "__main__":
    sys.exit(main())
