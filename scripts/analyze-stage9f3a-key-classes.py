#!/usr/bin/env python3
"""Analyze fixed-key versus varying-key signing traces."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


FIELDS = (
    "nanoseconds",
    "attempts",
    "reject_z",
    "reject_r0",
    "reject_ct0",
    "reject_hint",
    "total_rejections",
)


def load(path: Path) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []

    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            rows.append({key: int(value) for key, value in row.items()})

    return rows


def welch_t(left: list[float], right: list[float]) -> float:
    denominator = math.sqrt(
        statistics.variance(left) / len(left)
        + statistics.variance(right) / len(right)
    )
    return 0.0 if denominator == 0.0 else (
        statistics.fmean(left) - statistics.fmean(right)
    ) / denominator


def pearson(left: list[float], right: list[float]) -> float:
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


def linear_fit(
    x_values: list[float],
    y_values: list[float],
) -> tuple[float, float]:
    x_mean = statistics.fmean(x_values)
    y_mean = statistics.fmean(y_values)
    denominator = sum((x - x_mean) ** 2 for x in x_values)

    slope = (
        0.0
        if denominator == 0.0
        else sum(
            (x - x_mean) * (y - y_mean)
            for x, y in zip(x_values, y_values)
        )
        / denominator
    )
    intercept = y_mean - slope * x_mean
    return intercept, slope


def chi_square_two_class(
    left: Counter[int],
    right: Counter[int],
) -> float:
    categories = sorted(set(left) | set(right))
    left_total = sum(left.values())
    right_total = sum(right.values())
    grand_total = left_total + right_total
    statistic = 0.0

    for category in categories:
        column_total = left[category] + right[category]
        expected_left = left_total * column_total / grand_total
        expected_right = right_total * column_total / grand_total

        if expected_left > 0:
            statistic += (left[category] - expected_left) ** 2 / expected_left
        if expected_right > 0:
            statistic += (right[category] - expected_right) ** 2 / expected_right

    return statistic


def summarize_class(
    class_id: int,
    rows: list[dict[str, int]],
) -> None:
    print(f"class {class_id}: n={len(rows)}")
    print(
        f"  time mean={statistics.fmean(r['nanoseconds'] for r in rows):.2f} ns "
        f"median={statistics.median(r['nanoseconds'] for r in rows):.2f} ns"
    )
    print(
        f"  attempts mean={statistics.fmean(r['attempts'] for r in rows):.6f} "
        f"maximum={max(r['attempts'] for r in rows)}"
    )
    for field in ("reject_z", "reject_r0", "reject_ct0", "reject_hint"):
        print(f"  {field} total={sum(r[field] for r in rows)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    arguments = parser.parse_args()

    rows = load(arguments.csv)
    classes = {
        class_id: [row for row in rows if row["class"] == class_id]
        for class_id in (0, 1)
    }

    if min(len(classes[0]), len(classes[1])) < 2:
        raise SystemExit("both classes need at least two samples")

    summarize_class(0, classes[0])
    summarize_class(1, classes[1])

    class_zero_times = [
        float(row["nanoseconds"]) for row in classes[0]
    ]
    class_one_times = [
        float(row["nanoseconds"]) for row in classes[1]
    ]
    class_zero_attempts = [
        float(row["attempts"]) for row in classes[0]
    ]
    class_one_attempts = [
        float(row["attempts"]) for row in classes[1]
    ]

    print("\nwhole-class comparisons:")
    print(
        "  timing Welch t: "
        f"{welch_t(class_zero_times, class_one_times):.6f}"
    )
    print(
        "  attempts Welch t: "
        f"{welch_t(class_zero_attempts, class_one_attempts):.6f}"
    )

    attempt_counter_zero = Counter(
        row["attempts"] for row in classes[0]
    )
    attempt_counter_one = Counter(
        row["attempts"] for row in classes[1]
    )
    print(
        "  attempt-distribution chi-square: "
        f"{chi_square_two_class(attempt_counter_zero, attempt_counter_one):.6f}"
    )

    attempts = [float(row["attempts"]) for row in rows]
    times = [float(row["nanoseconds"]) for row in rows]
    intercept, slope = linear_fit(attempts, times)
    residuals = [
        time - (intercept + slope * attempt)
        for time, attempt in zip(times, attempts)
    ]

    residual_by_class = {
        class_id: [
            residual
            for row, residual in zip(rows, residuals)
            if row["class"] == class_id
        ]
        for class_id in (0, 1)
    }

    print("\nattempt-count regression:")
    print(f"  intercept: {intercept:.2f} ns")
    print(f"  per-attempt slope: {slope:.2f} ns")
    print(
        "  time/attempt Pearson correlation: "
        f"{pearson(times, attempts):.6f}"
    )
    print(
        "  residual timing Welch t: "
        f"{welch_t(residual_by_class[0], residual_by_class[1]):.6f}"
    )

    print("\nwithin-attempt timing comparisons:")
    grouped: dict[int, dict[int, list[float]]] = defaultdict(
        lambda: {0: [], 1: []}
    )
    for row in rows:
        grouped[row["attempts"]][row["class"]].append(
            float(row["nanoseconds"])
        )

    tested_buckets = 0
    maximum_absolute_t = 0.0

    for attempt in sorted(grouped):
        left = grouped[attempt][0]
        right = grouped[attempt][1]

        if len(left) < 20 or len(right) < 20:
            continue

        statistic = welch_t(left, right)
        maximum_absolute_t = max(maximum_absolute_t, abs(statistic))
        tested_buckets += 1
        print(
            f"  attempts={attempt}: "
            f"n0={len(left)} n1={len(right)} "
            f"t={statistic:.6f}"
        )

    print(f"  tested buckets: {tested_buckets}")
    print(
        "  maximum absolute within-attempt t: "
        f"{maximum_absolute_t:.6f}"
    )

    print("\nrejection-category mean comparisons:")
    for field in ("reject_z", "reject_r0", "reject_ct0", "reject_hint"):
        left = [float(row[field]) for row in classes[0]]
        right = [float(row[field]) for row in classes[1]]

        if statistics.variance(left) == 0 and statistics.variance(right) == 0:
            statistic = 0.0
        else:
            statistic = welch_t(left, right)

        print(
            f"  {field}: "
            f"mean0={statistics.fmean(left):.6f} "
            f"mean1={statistics.fmean(right):.6f} "
            f"t={statistic:.6f}"
        )

    print(
        "\ninterpretation: investigate |t| >= 4.5 for attempts, "
        "residual timing, sufficiently populated within-attempt buckets, "
        "or rejection-category means"
    )


if __name__ == "__main__":
    main()
