#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path


def correlation(left: list[float], right: list[float]) -> float:
    left_mean = statistics.fmean(left)
    right_mean = statistics.fmean(right)
    numerator = sum(
        (x - left_mean) * (y - right_mean)
        for x, y in zip(left, right)
    )
    denominator = math.sqrt(
        sum((x - left_mean) ** 2 for x in left)
        * sum((y - right_mean) ** 2 for y in right)
    )
    return 0.0 if denominator == 0.0 else numerator / denominator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    args = parser.parse_args()

    rows = []
    with args.csv.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            rows.append({key: int(value) for key, value in row.items()})

    times = [row["nanoseconds"] for row in rows]
    attempts = [row["attempts"] for row in rows]

    print(f"cases: {len(rows)}")
    print(f"mean signing time: {statistics.fmean(times):.2f} ns")
    print(f"median signing time: {statistics.median(times):.2f} ns")
    print(f"mean attempts: {statistics.fmean(attempts):.4f}")
    print(f"maximum attempts: {max(attempts)}")
    print(
        "time/attempt Pearson correlation: "
        f"{correlation(times, attempts):.6f}"
    )

    by_attempt = defaultdict(list)
    for row in rows:
        by_attempt[row["attempts"]].append(row["nanoseconds"])

    print("\nlatency by attempt count:")
    for attempt in sorted(by_attempt):
        values = by_attempt[attempt]
        print(
            f"  attempts={attempt}: n={len(values)} "
            f"mean={statistics.fmean(values):.2f} ns "
            f"median={statistics.median(values):.2f} ns"
        )

    print("\nrejection totals:")
    for field in ("reject_z", "reject_r0", "reject_ct0", "reject_hint"):
        values = [row[field] for row in rows]
        print(f"  {field}: {sum(values)}")

    print(
        "\ninterpretation: strong positive correlation is expected from "
        "rejection sampling; the next question is whether rejection "
        "categories or accepted transcript properties expose additional "
        "secret-dependent structure beyond attempt count"
    )


if __name__ == "__main__":
    main()
