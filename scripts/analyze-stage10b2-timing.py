#!/usr/bin/env python3
"""Analyze Stage 10B-2 mismatch-position timing results."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path


def welch_t(left: list[float], right: list[float]) -> float:
    """Return the Welch t-statistic for two sample sets."""
    denominator = math.sqrt(
        statistics.variance(left) / len(left)
        + statistics.variance(right) / len(right)
    )

    if denominator == 0.0:
        return 0.0

    return (
        statistics.fmean(left) - statistics.fmean(right)
    ) / denominator


def main() -> None:
    """Load timing samples, compare classes, and enforce the threshold."""
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    arguments = parser.parse_args()

    classes: dict[int, list[float]] = defaultdict(list)

    with arguments.csv.open(
        newline="",
        encoding="utf-8",
    ) as stream:
        for row in csv.DictReader(stream):
            classes[int(row["class"])].append(
                float(row["nanoseconds"])
            )

    labels = {
        0: "first-byte mismatch",
        1: "middle-byte mismatch",
        2: "last-byte mismatch",
        3: "equal",
    }

    missing_classes = set(labels) - set(classes)

    if missing_classes:
        missing = ", ".join(
            str(value) for value in sorted(missing_classes)
        )
        raise SystemExit(f"missing timing classes: {missing}")

    for class_id in sorted(labels):
        values = classes[class_id]

        if len(values) < 2:
            raise SystemExit(
                f"class {class_id} has insufficient samples"
            )

        print(
            f"class {class_id} ({labels[class_id]}): "
            f"n={len(values)} "
            f"mean={statistics.fmean(values):.4f} ns "
            f"median={statistics.median(values):.4f} ns"
        )

    comparisons = (
        (0, 1),
        (0, 2),
        (1, 2),
        (0, 3),
        (1, 3),
        (2, 3),
    )
    maximum = 0.0

    print("\nWelch t comparisons:")

    for left, right in comparisons:
        statistic = welch_t(classes[left], classes[right])
        maximum = max(maximum, abs(statistic))

        print(
            f"  {labels[left]} vs {labels[right]}: "
            f"t={statistic:.6f}"
        )

    print(f"\nmaximum absolute t: {maximum:.6f}")

    if maximum >= 4.5:
        print(
            "classification: timing-class separation detected"
        )
        raise SystemExit(1)

    print(
        "classification: no timing signal detected "
        "at this sample size"
    )


if __name__ == "__main__":
    main()
