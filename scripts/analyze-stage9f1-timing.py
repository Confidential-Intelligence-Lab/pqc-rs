#!/usr/bin/env python3
"""Analyze an interleaved timing screen with Welch's t-test."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path


def load(path: Path) -> tuple[list[float], list[float]]:
    classes: tuple[list[float], list[float]] = ([], [])

    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            class_id = int(row["class"])
            if class_id not in (0, 1):
                raise ValueError(f"invalid class {class_id}")
            classes[class_id].append(float(row["nanoseconds"]))

    return classes


def trimmed(values: list[float], fraction: float) -> list[float]:
    if not 0.0 <= fraction < 0.5:
        raise ValueError("trim fraction must be in [0, 0.5)")

    ordered = sorted(values)
    cut = int(len(ordered) * fraction)
    return ordered[cut : len(ordered) - cut] if cut else ordered


def welch_t(left: list[float], right: list[float]) -> float:
    denominator = math.sqrt(
        statistics.variance(left) / len(left)
        + statistics.variance(right) / len(right)
    )
    return (
        0.0
        if denominator == 0.0
        else (statistics.fmean(left) - statistics.fmean(right)) / denominator
    )


def describe(name: str, values: list[float]) -> None:
    print(
        f"{name}: n={len(values)} "
        f"mean={statistics.fmean(values):.2f} ns "
        f"median={statistics.median(values):.2f} ns "
        f"stdev={statistics.stdev(values):.2f} ns"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("--trim", type=float, default=0.01)
    arguments = parser.parse_args()

    class_zero, class_one = load(arguments.csv)
    if len(class_zero) < 2 or len(class_one) < 2:
        raise SystemExit("both classes require at least two samples")

    describe("class 0 raw", class_zero)
    describe("class 1 raw", class_one)
    raw_t = welch_t(class_zero, class_one)
    print(f"raw Welch t: {raw_t:.4f}")

    zero_trimmed = trimmed(class_zero, arguments.trim)
    one_trimmed = trimmed(class_one, arguments.trim)
    describe("class 0 trimmed", zero_trimmed)
    describe("class 1 trimmed", one_trimmed)
    trimmed_t = welch_t(zero_trimmed, one_trimmed)
    print(f"trimmed Welch t: {trimmed_t:.4f}")

    maximum = max(abs(raw_t), abs(trimmed_t))
    if maximum >= 10.0:
        result = "strong timing-class separation"
    elif maximum >= 4.5:
        result = "timing signal requiring investigation"
    else:
        result = "no timing signal detected at this sample size"

    print(f"classification: {result}")
    print(
        "note: non-detection is not proof of constant-time behavior; "
        "repeat across machines, sample sizes, and compiler settings"
    )


if __name__ == "__main__":
    main()
