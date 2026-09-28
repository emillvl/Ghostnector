#!/usr/bin/env python3
"""Corrected resource sampling: /proc deltas, not lifetime ps averages.

Usage:
  perf-resources.py --label IDLE --seconds 60 --match product|baseline|relay|all

Samples every matching process at t0 and t1 and reports:
  * CPU% over the interval from /proc/<pid>/stat utime+stime deltas
  * mean VmRSS
  * voluntary / nonvoluntary context-switch deltas
  * the whole-system CPU% from /proc/stat, for context

Matching is by exact argv[0] suffix or by an argument token containing a substring, so a
process that merely *names* another binary in its arguments (core with --dns-helper, a
runuser wrapper for tor) is not mistaken for it.
"""

import argparse
import os
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")

# (label, kind, value); kind=argv0 means the basename of argv[0] must equal value;
# kind=token means any argv token must contain value.
MATCHERS = {
    "product": [
        ("netd", "argv0", "ghostnector-netd"),
        ("core", "argv0", "ghostnector-core"),
        ("appd", "argv0", "ghostnector-appd"),
        ("dns", "argv0", "ghostnector-dns"),
        ("tor", "token", "/run/ghostnector/torrc"),
    ],
    "baseline": [("baseline-tor", "token", "gh-paired-torrc")],
    "relay": [("relay", "argv0", "ghostnector-appd-relay")],
}


def matches(tokens, kind, value):
    if not tokens:
        return False
    if kind == "argv0":
        return os.path.basename(tokens[0]) == value
    return any(value in token for token in tokens)


def read_processes(kind, value):
    found = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                cmdline = handle.read().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        tokens = cmdline.split()
        if matches(tokens, kind, value):
            found[entry] = cmdline.strip()
    return found


def sample(pid):
    with open(f"/proc/{pid}/stat", "r") as handle:
        stat = handle.read()
    rest = stat[stat.rfind(")") + 2 :].split()
    utime, stime = int(rest[11]), int(rest[12])
    rss = 0
    vol = nonvol = 0
    with open(f"/proc/{pid}/status", "r") as handle:
        for line in handle:
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
            elif line.startswith("voluntary_ctxt_switches:"):
                vol = int(line.split()[1])
            elif line.startswith("nonvoluntary_ctxt_switches:"):
                nonvol = int(line.split()[1])
    return {"ticks": utime + stime, "rss": rss, "vol": vol, "nonvol": nonvol}


def system_cpu():
    with open("/proc/stat", "r") as handle:
        parts = handle.readline().split()
    values = [int(value) for value in parts[1:]]
    idle = values[3] + values[4]
    return sum(values), idle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--seconds", type=float, default=60.0)
    parser.add_argument("--out", default="")
    parser.add_argument("--match", default="product")
    args = parser.parse_args()

    specs = []
    if args.match == "all":
        for group in MATCHERS.values():
            specs.extend(group)
    else:
        specs = MATCHERS[args.match]

    pids = {}
    for label, kind, value in specs:
        processes = read_processes(kind, value)
        if processes:
            pid = sorted(processes)[0]
            pids[label] = (pid, processes[pid])
            print(f"# {label}: pid {pid}: {processes[pid][:100]}")
        else:
            print(f"# {label}: not running")

    user, idle = system_cpu()
    before = {label: sample(pid) for label, (pid, _) in pids.items()}
    began = time.monotonic()
    time.sleep(args.seconds)
    elapsed = time.monotonic() - began
    after = {label: sample(pid) for label, (pid, _) in pids.items()}
    user2, idle2 = system_cpu()

    print(f"\n== {args.label} resources over {elapsed:.1f}s ==")
    print(f"{'process':12s} {'cpu%':>7s} {'rss_kb':>9s} {'vol_sw':>8s} {'nonvol_sw':>9s}")
    for label in sorted(before):
        first, last = before[label], after[label]
        cpu = 100.0 * (last["ticks"] - first["ticks"]) / CLK_TCK / elapsed
        rss = (first["rss"] + last["rss"]) / 2
        print(
            f"{label:12s} {cpu:7.3f} {rss:9.0f} "
            f"{last['vol'] - first['vol']:8d} {last['nonvol'] - first['nonvol']:9d}"
        )
    total = user2 - user
    busy = total - (idle2 - idle)
    print(f"system cpu over window: {100.0 * busy / max(total, 1):.1f}% of all cores")


if __name__ == "__main__":
    main()
