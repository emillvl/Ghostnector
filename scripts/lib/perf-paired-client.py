#!/usr/bin/env python3
"""One HTTP sample for the Ghostnector paired performance benchmark.

Three routes, each exercised exactly once per invocation:

  product     an explicit DNS query to a FOREIGN resolver, then an HTTP connection to the
              resolved address. Run as the protected uid, the kernel policy redirects both
              to the product's DNS chokepoint and TransPort. This is the shape every
              application takes on a transparent proxy.
  equivalent  the same, but the bench-level nft chain (priority -150) redirects the sample
              uid's DNS to a standalone Tor's DNSPort and its TCP to that Tor's TransPort.
              Same fundamental transparent shape, no Ghostnector code in the path.
  socks       the name is handed to the standalone Tor's SocksPort in a SOCKS5 CONNECT
              (secondary reference only: this resolves at the exit, so it is NOT the
              equivalent baseline).

Output: one CSV line on stdout (the orchestrator appends it to the raw sample file):

  iter,epoch,route,ok,dns_ms,connect_ms,socks_ms,ttfb_ms,body_ms,total_ms,bytes,exit_ip,note

Never raises: a failed sample is a row with ok=0 and a note.
"""

import argparse
import socket
import struct
import sys
import time

FOREIGN_RESOLVER = ("8.8.8.8", 53)
DNS_ID = 0x4748


def build_query(name: str) -> bytes:
    q = struct.pack("!HHHHHH", DNS_ID, 0x0100, 1, 0, 0, 0)
    for label in name.rstrip(".").split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", 1, 1)
    return q


def skip_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def parse_first_a(data: bytes):
    """Return (rcode, first A address or None). Raises ValueError on malformed input."""
    if len(data) < 12:
        raise ValueError("short DNS answer")
    ident, flags, qd, an = struct.unpack("!HHHH", data[:8])
    if ident != DNS_ID:
        raise ValueError("DNS id mismatch")
    rcode = flags & 0xF
    offset = 12
    for _ in range(qd):
        offset = skip_name(data, offset) + 4
    address = None
    for _ in range(an):
        offset = skip_name(data, offset)
        kind, cls, _ttl, length = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if kind == 1 and cls == 1 and length == 4 and address is None:
            address = socket.inet_ntoa(data[offset : offset + 4])
        offset += length
    return rcode, address


def dns_lookup(name: str, timeout: float):
    query = build_query(name)
    last = None
    for _ in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            began = time.perf_counter()
            sock.sendto(query, FOREIGN_RESOLVER)
            data, _ = sock.recvfrom(4096)
            elapsed = (time.perf_counter() - began) * 1000.0
            rcode, address = parse_first_a(data)
            if rcode != 0:
                raise RuntimeError(f"DNS rcode {rcode}")
            if not address:
                raise RuntimeError("DNS answer carried no A record")
            return address, elapsed
        except (socket.timeout, OSError) as error:
            last = error
        finally:
            sock.close()
    raise RuntimeError(f"dns: {last}")


def read_response(sock: socket.socket, first_byte_at):
    """Read the whole response; return a dict with status, exit IP and timings."""
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


def timed_http(sock: socket.socket, host: str, path: str):
    request = (
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
        "Connection: close\r\nUser-Agent: gh-perf-paired\r\n\r\n"
    )
    began = time.perf_counter()
    sock.sendall(request.encode())
    return read_response(sock, began)


def path_transparent(args):
    address, dns_ms = dns_lookup(args.host, args.timeout)
    began = time.perf_counter()
    sock = socket.create_connection((address, args.port), timeout=args.timeout)
    out = {"dns_ms": dns_ms, "socks_ms": "", "connect_ms": (time.perf_counter() - began) * 1000.0}
    sock.settimeout(args.timeout)
    try:
        out.update(timed_http(sock, args.host, args.http_path))
    finally:
        sock.close()
    return out


def socks_reply(sock: socket.socket):
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


def path_socks(args):
    began = time.perf_counter()
    sock = socket.create_connection(("127.0.0.1", args.socks_port), timeout=args.timeout)
    out = {"dns_ms": "", "connect_ms": (time.perf_counter() - began) * 1000.0}
    sock.settimeout(args.timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        choice = sock.recv(2)
        if len(choice) != 2 or choice[0] != 5:
            raise RuntimeError(f"SOCKS greeting refused: {choice!r}")
        name = args.host.encode()
        request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", args.port)
        began = time.perf_counter()
        sock.sendall(request)
        socks_reply(sock)
        out["socks_ms"] = (time.perf_counter() - began) * 1000.0
        out.update(timed_http(sock, args.host, args.http_path))
    finally:
        sock.close()
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--route", required=True, choices=["product", "equivalent", "socks"])
    parser.add_argument("--iter", type=int, default=0)
    parser.add_argument("--host", required=True)
    parser.add_argument("--http-path", default="/")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--socks-port", type=int, default=19050)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--tag", default="latency")
    args = parser.parse_args()

    began = time.perf_counter()
    row = {
        "dns_ms": "",
        "connect_ms": "",
        "socks_ms": "",
        "ttfb_ms": "",
        "body_ms": "",
        "bytes": 0,
        "exit_ip": "",
        "note": args.tag,
    }
    ok = 0
    try:
        if args.route == "socks":
            result = path_socks(args)
        else:
            result = path_transparent(args)
        row.update(result)
        if not result.get("status_ok", False):
            row["note"] = f"{args.tag}:http:{result.get('status_line', '')}"[:80]
        else:
            ok = 1
    except Exception as error:  # noqa: BLE001 - a failed sample is a row
        row["note"] = f"{args.tag}:{type(error).__name__}:{error}"[:120]
    total_ms = (time.perf_counter() - began) * 1000.0
    for key in ("dns_ms", "connect_ms", "socks_ms", "ttfb_ms", "body_ms"):
        if isinstance(row[key], float):
            row[key] = f"{row[key]:.2f}"
    print(
        ",".join(
            [
                str(args.iter),
                f"{time.time():.3f}",
                f"route_{args.route}",
                str(ok),
                str(row["dns_ms"]),
                str(row["connect_ms"]),
                str(row["socks_ms"]),
                str(row["ttfb_ms"]),
                str(row["body_ms"]),
                f"{total_ms:.2f}",
                str(row["bytes"]),
                str(row["exit_ip"]),
                str(row["note"]).replace(",", ";"),
            ]
        )
    )


if __name__ == "__main__":
    sys.exit(main())
