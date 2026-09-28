#!/usr/bin/env python3
"""Summarize the raw samples of the paired HTTP benchmark.

Reads the CSV the orchestrator wrote and prints, for the log and for the campaign record:

  * per route: usable count, p10 / median / p90 for dns, connect, ttfb, body, total
  * paired product - equivalent differences (per iteration), which is the number the
    campaign is about
  * the secondary socks reference, for context only
  * throughput rows (bytes > 100000) as MiB/s

Usage: perf-paired-summary.py SAMPLES.csv
"""

import csv
import statistics
import sys


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def number(row, key):
    value = row.get(key, "")
    if value in ("", None):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def stats(values):
    if not values:
        return "n=0"
    return (
        f"n={len(values)} p10={percentile(values, 0.10):.1f} "
        f"med={statistics.median(values):.1f} p90={percentile(values, 0.90):.1f}"
    )


def main():
    path = sys.argv[1]
    rows = []
    with open(path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            rows.append(row)

    routes = ["route_product", "route_equivalent", "route_socks"]
    print("== paired HTTP samples ==")
    print(f"samples: {len(rows)}")

    for route in routes:
        subset = [row for row in rows if row["route"] == route]
        usable = [row for row in subset if row["ok"] == "1"]
        failed = [row for row in subset if row["ok"] != "1"]
        print(f"\n-- {route}: {len(usable)} usable / {len(subset)} attempted --")
        if failed:
            reasons = {}
            for row in failed:
                reasons[row["note"]] = reasons.get(row["note"], 0) + 1
            for reason, count in sorted(reasons.items(), key=lambda item: -item[1])[:3]:
                print(f"   failed x{count}: {reason}")
        for field in ("dns_ms", "connect_ms", "socks_ms", "ttfb_ms", "body_ms", "total_ms"):
            values = [number(row, field) for row in usable]
            values = [value for value in values if value is not None]
            if values:
                print(f"   {field:10s} {stats(values)}")

    def paired(route_a, route_b):
        by_iter_b = {}
        for row in rows:
            if row["route"] == route_b and row["ok"] == "1":
                by_iter_b.setdefault(row["iter"], row)
        differences = []
        for row in rows:
            if row["route"] != route_a or row["ok"] != "1":
                continue
            other = by_iter_b.get(row["iter"])
            if other is None:
                continue
            a = number(row, "total_ms")
            b = number(other, "total_ms")
            if a is not None and b is not None:
                differences.append(a - b)
        if differences:
            print(
                f"\npaired {route_a} - {route_b} (total_ms): "
                f"n={len(differences)} p10={percentile(differences, 0.10):.1f} "
                f"med={statistics.median(differences):.1f} "
                f"p90={percentile(differences, 0.90):.1f} "
                f"mean={statistics.mean(differences):.1f}"
            )
        else:
            print(f"\npaired {route_a} - {route_b}: no usable pairs")
        return differences

    paired("route_product", "route_equivalent")
    paired("route_product", "route_socks")
    paired("route_equivalent", "route_socks")

    print("\n== throughput rows (bytes > 100000) ==")
    for route in routes:
        speeds = []
        for row in rows:
            if row["route"] != route or row["ok"] != "1":
                continue
            size = number(row, "bytes") or 0
            body = number(row, "body_ms")
            if size > 100000 and body and body > 0:
                speeds.append(size / 1e6 / (body / 1000.0))
        if speeds:
            print(
                f"-- {route}: n={len(speeds)} med={statistics.median(speeds):.2f} MiB/s "
                f"p10={percentile(speeds, 0.10):.2f} p90={percentile(speeds, 0.90):.2f}"
            )
        else:
            print(f"-- {route}: no throughput rows")


if __name__ == "__main__":
    main()
