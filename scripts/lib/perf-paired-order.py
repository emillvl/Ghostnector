#!/usr/bin/env python3
"""Order-aware paired analysis for the campaign report.

Beyond perf-paired-analysis.py, this checks whether the within-iteration route order
(product first vs equivalent first) explains part of the paired difference, and prints the
DNS/TTFB differences split by order. If the difference follows the order, it is an
artifact of who warms the exit resolver/circuit first, not a route property.
"""

import csv
import statistics
import sys


def number(row, key):
    try:
        return float(row[key])
    except (KeyError, ValueError):
        return None


def main():
    for path in sys.argv[1:]:
        rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
        latency = [row for row in rows if row["note"] in ("latency", "warmup")]
        by_iter = {}
        for index, row in enumerate(latency):
            by_iter.setdefault(row["iter"], []).append((index, row))
        pairs = []
        for iteration, entries in by_iter.items():
            if len(entries) < 3:
                continue
            product = next((row for _, row in entries if row["route"] == "route_product"), None)
            equivalent = next(
                (row for _, row in entries if row["route"] == "route_equivalent"), None
            )
            if product is None or equivalent is None:
                continue
            if product["ok"] != "1" or equivalent["ok"] != "1":
                continue
            order = [
                index
                for index, row in entries
                if row["route"] in ("route_product", "route_equivalent")
            ]
            product_index = next(index for index, row in entries if row["route"] == "route_product")
            equivalent_index = next(
                index for index, row in entries if row["route"] == "route_equivalent"
            )
            pairs.append(
                {
                    "iter": iteration,
                    "order": "product-first" if product_index < equivalent_index else "equivalent-first",
                    "total_diff": number(product, "total_ms") - number(equivalent, "total_ms"),
                    "dns_diff": number(product, "dns_ms") - number(equivalent, "dns_ms"),
                    "ttfb_diff": number(product, "ttfb_ms") - number(equivalent, "ttfb_ms"),
                }
            )
        print(f"\n#### {path}: {len(pairs)} paired latency iterations")
        for field in ("total_diff", "dns_diff", "ttfb_diff"):
            values = [pair[field] for pair in pairs if pair[field] is not None]
            if values:
                print(
                    f"{field:10s} n={len(values):3d} p10={sorted(values)[int(0.1*(len(values)-1))]:8.1f} "
                    f"med={statistics.median(values):8.1f} "
                    f"p90={sorted(values)[int(0.9*(len(values)-1))]:8.1f} "
                    f"mean={statistics.mean(values):8.1f}"
                )
        for order in ("product-first", "equivalent-first"):
            subset = [pair for pair in pairs if pair["order"] == order]
            for field in ("total_diff", "dns_diff", "ttfb_diff"):
                values = [pair[field] for pair in subset if pair[field] is not None]
                if values:
                    print(
                        f"  {order:18s} {field:10s} n={len(values):2d} "
                        f"med={statistics.median(values):8.1f} mean={statistics.mean(values):8.1f}"
                    )


if __name__ == "__main__":
    main()
