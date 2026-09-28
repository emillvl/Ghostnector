#!/usr/bin/env python3
"""Summarize an APP launch profile CSV: mode medians and the product's phase gaps.

Usage: perf-app-launch-analysis.py CSV
"""

import csv
import statistics
import sys


def number(row, key):
    try:
        return float(row[key])
    except (KeyError, ValueError):
        return None


def median_of(rows, key):
    values = [number(row, key) for row in rows]
    values = [value for value in values if value is not None]
    return statistics.median(values) if values else None


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[int(round(fraction * (len(ordered) - 1)))]


def main():
    rows = list(csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")))
    for mode in ("direct", "product"):
        subset = [row for row in rows if row["mode"] == mode]
        print(f"-- {mode}: {len(subset)} runs")
        for field in ("app_ms", "exec_ms", "netns_ms", "relay_ms", "session_ms", "launcher_ms"):
            values = [number(row, field) for row in subset]
            values = [value for value in values if value is not None]
            if values:
                print(
                    f"   {field:10s} n={len(values):2d} p10={percentile(values, 0.10):7.1f} "
                    f"med={statistics.median(values):7.1f} p90={percentile(values, 0.90):7.1f} "
                    f"min={min(values):7.1f} max={max(values):7.1f}"
                )
    product = [row for row in rows if row["mode"] == "product"]
    direct = [row for row in rows if row["mode"] == "direct"]
    if not product or not direct:
        return
    netns = median_of(product, "netns_ms")
    relay = median_of(product, "relay_ms")
    app = median_of(product, "app_ms")
    direct_app = median_of(direct, "app_ms")
    print("\nproduct phase gaps (medians):")
    print(f"   t0 -> netns      {netns:7.1f} ms   CLI + core IPC + appd Create start")
    print(f"   netns -> relay   {relay - netns:7.1f} ms   namespace config + nft + relay spawn")
    print(f"   relay -> app     {app - relay:7.1f} ms   Create return + Launch + session + launcher + exec")
    print(f"   t0 -> app        {app:7.1f} ms")
    print(f"   direct t0 -> app {direct_app:7.1f} ms")
    print(f"   product-added    {app - direct_app:7.1f} ms")


if __name__ == "__main__":
    main()
