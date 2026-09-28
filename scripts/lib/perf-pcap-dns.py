#!/usr/bin/env python3
"""Per-query DNS timing from a loopback pcap, for the chokepoint focus run.

Usage: perf-pcap-dns.py CAPTURE.pcap

The focus run issues strictly sequential queries, so packets can be attributed by order:

  chokepoint route:  client:P -> 127.0.0.1:53   (Q1)
                     relay:E  -> 127.0.0.1:9053 (Q2, upstream)
                     127.0.0.1:9053 -> relay:E   (R1)
                     127.0.0.1:53 -> client:P    (R2)
  equivalent route:  client:P -> 127.0.0.1:9053
                     127.0.0.1:9053 -> client:P

Reports, for both routes, the client-observed RTT and (for the chokepoint route) the
relay's own upstream RTT and its queueing/handling time on both sides.
"""

import struct
import sys
from collections import namedtuple

Packet = namedtuple("Packet", "time src sport dst dport size")

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def read_packets(path):
    with open(path, "rb") as handle:
        data = handle.read()
    magic = data[:4]
    endian, scale = PCAP_MAGIC[magic]
    offset = 24
    packets = []
    while offset + 16 <= len(data):
        sec, frac, captured, _original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        frame = data[offset : offset + captured]
        offset += captured
        if len(frame) < 14 + 20 + 8:
            continue
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        if ethertype != 0x0800:
            continue
        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17:  # UDP
            continue
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        udp = ip[ihl:]
        sport, dport, length = struct.unpack_from(">HHH", udp, 0)
        packets.append(
            Packet(sec + frac / scale, src, sport, dst, dport, length)
        )
    packets.sort(key=lambda packet: packet.time)
    return packets


def classify(packet):
    if packet.dst == "127.0.0.1" and packet.dport == 53 and packet.sport != 53:
        return "q1"
    if packet.src == "127.0.0.1" and packet.sport == 53 and packet.dport != 53:
        return "r2"
    if packet.dst == "127.0.0.1" and packet.dport == 9053 and packet.sport != 9053:
        return "q2"
    if packet.src == "127.0.0.1" and packet.sport == 9053:
        return "r1"
    return "other"


def stats(values):
    if not values:
        return "n=0"
    ordered = sorted(values)
    return (
        f"n={len(ordered)} p10={ordered[int(0.1 * (len(ordered) - 1))]:.1f} "
        f"med={ordered[len(ordered) // 2]:.1f} p90={ordered[int(0.9 * (len(ordered) - 1))]:.1f}"
    )


def main():
    packets = read_packets(sys.argv[1])
    chokepoint = {"q1_to_r2": [], "q1_to_q2": [], "q2_to_r1": [], "r1_to_r2": []}
    equivalent = {"q2_to_r1": []}
    pending_q1 = None
    pending_relay_q2 = None
    pending_direct_q2 = None
    pending_relay_r1 = None
    for packet in packets:
        kind = classify(packet)
        if kind == "q1":
            # A new chokepoint-shaped query resets the attribution window.
            pending_q1 = packet
            pending_relay_q2 = None
            pending_relay_r1 = None
        elif kind == "q2":
            if pending_q1 is not None and pending_relay_q2 is None:
                pending_relay_q2 = packet
                chokepoint["q1_to_q2"].append((packet.time - pending_q1.time) * 1000)
            else:
                pending_direct_q2 = packet
        elif kind == "r1":
            if pending_q1 is not None and pending_relay_q2 is not None:
                pending_relay_r1 = packet
                chokepoint["q2_to_r1"].append((packet.time - pending_relay_q2.time) * 1000)
            elif pending_direct_q2 is not None:
                equivalent["q2_to_r1"].append((packet.time - pending_direct_q2.time) * 1000)
                pending_direct_q2 = None
        elif kind == "r2":
            if pending_q1 is not None:
                chokepoint["q1_to_r2"].append((packet.time - pending_q1.time) * 1000)
                if pending_relay_r1 is not None:
                    chokepoint["r1_to_r2"].append((packet.time - pending_relay_r1.time) * 1000)
            pending_q1 = None
            pending_relay_q2 = None
            pending_relay_r1 = None
            pending_direct_q2 = None
    print("chokepoint route (client -> chokepoint -> DNSPort -> chokepoint -> client):")
    print(f"  client to relay        {stats(chokepoint['q1_to_q2'])} ms")
    print(f"  relay upstream RTT     {stats(chokepoint['q2_to_r1'])} ms")
    print(f"  relay reply to client  {stats(chokepoint['r1_to_r2'])} ms")
    print(f"  client-observed total  {stats(chokepoint['q1_to_r2'])} ms")
    print("\nequivalent/direct route (client -> DNSPort -> client):")
    print(f"  client-observed total  {stats(equivalent['q2_to_r1'])} ms")


if __name__ == "__main__":
    sys.exit(main())
