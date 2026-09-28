#!/usr/bin/env python3
"""Paired-difference analysis with confidence intervals for the campaign record.

Usage: perf-paired-analysis.py LABEL=FILE.csv [LABEL=FILE.csv ...]

For each run it prints per-route distributions and the paired product - equivalent
difference with a bootstrap 95% CI and a two-sided sign test, which is the honest way to
ask whether a difference is distinguishable from the observed variance.
"""

import csv
import math
import random
import statistics
import sys


def load(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def number(row, key):
    try:
        return float(row[key])
    except (KeyError, ValueError):
        return None


def percentile(values, fraction):
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def bootstrap_ci(values, samples=10000, seed=20260928):
    random.seed(seed)
    medians = []
    n = len(values)
    for _ in range(samples):
        medians.append(statistics.median(values[random.randrange(n)] for _ in range(n)))
    medians.sort()
    return medians[int(0.025 * samples)], medians[int(0.975 * samples)]


def sign_test(values):
    positive = sum(1 for value in values if value > 0)
    negative = sum(1 for value in values if value < 0)
    n = positive + negative
    if n == 0:
        return 1.0
    k = min(positive, negative)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2**n)
    return min(1.0, 2 * tail)


def main():
    for argument in sys.argv[1:]:
        label, path = argument.split("=", 1)
        rows = load(path)
        print(f"\n######## {label} ########")
        by_route = {}
        for row in rows:
            by_route.setdefault(row["route"], []).append(row)
        for route in sorted(by_route):
            usable = [row for row in by_route[route] if row["ok"] == "1"]
            totals = [number(row, "total_ms") for row in usable]
            totals = [value for value in totals if value is not None]
            print(f"-- {route}: {len(usable)} usable / {len(by_route[route])} attempted")
            for field in ("dns_ms", "connect_ms", "socks_ms", "ttfb_ms", "total_ms"):
                values = [number(row, field) for row in usable]
                values = [value for value in values if value is not None]
                if values:
                    print(
                        f"   {field:10s} n={len(values):3d} p10={percentile(values, 0.10):8.1f} "
                        f"med={statistics.median(values):8.1f} p90={percentile(values, 0.90):8.1f}"
                    )
        # Paired product - equivalent, matched by iteration; only the latency windows.
        equivalent = {
            row["iter"]: row
            for row in by_route.get("route_equivalent", [])
            if row["ok"] == "1"
        }
        differences = []
        dns_differences = []
        ttfb_differences = []
        for row in by_route.get("route_product", []):
            if row["ok"] != "1":
                continue
            other = equivalent.get(row["iter"])
            if other is None:
                continue
            first, second = number(row, "total_ms"), number(other, "total_ms")
            if first is not None and second is not None:
                differences.append(first - second)
            first, second = number(row, "dns_ms"), number(other, "dns_ms")
            if first is not None and second is not None:
                dns_differences.append(first - second)
            first, second = number(row, "ttfb_ms"), number(other, "ttfb_ms")
            if first is not None and second is not None:
                ttfb_differences.append(first - second)
        if differences:
            low, high = bootstrap_ci(differences)
            print(
                f"\npaired product - equivalent (total_ms): n={len(differences)} "
                f"p10={percentile(differences, 0.10):.1f} med={statistics.median(differences):.1f} "
                f"p90={percentile(differences, 0.90):.1f} mean={statistics.mean(differences):.1f}"
            )
            print(
                f"bootstrap 95% CI of the median: [{low:.1f}, {high:.1f}]  "
                f"sign-test p={sign_test(differences):.4f}  "
                f"product faster in {sum(1 for value in differences if value < 0)}/{len(differences)}"
            )
        if dns_differences:
            low, high = bootstrap_ci(dns_differences)
            print(
                f"paired DNS difference: n={len(dns_differences)} "
                f"med={statistics.median(dns_differences):.1f} "
                f"95% CI [{low:.1f}, {high:.1f}]"
            )
        if ttfb_differences:
            low, high = bootstrap_ci(ttfb_differences)
            print(
                f"paired TTFB difference: n={len(ttfb_differences)} "
                f"med={statistics.median(ttfb_differences):.1f} "
                f"95% CI [{low:.1f}, {high:.1f}]"
            )


if __name__ == "__main__":
    main()
