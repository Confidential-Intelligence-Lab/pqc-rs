#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import math
import statistics
from pathlib import Path


def load(path: Path) -> tuple[list[float], list[float]]:
    classes = ([], [])
    with path.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            classes[int(row["class"])].append(float(row["nanoseconds"]))
    return classes


def trim(values: list[float], fraction: float = 0.01) -> list[float]:
    values = sorted(values)
    cut = int(len(values) * fraction)
    return values[cut:-cut] if cut else values


def welch(left: list[float], right: list[float]) -> float:
    denominator = math.sqrt(
        statistics.variance(left) / len(left)
        + statistics.variance(right) / len(right)
    )
    return 0.0 if denominator == 0.0 else (
        statistics.fmean(left) - statistics.fmean(right)
    ) / denominator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    args = parser.parse_args()

    left, right = load(args.csv)
    raw = welch(left, right)
    trimmed = welch(trim(left), trim(right))
    maximum = max(abs(raw), abs(trimmed))

    print(f"class 0 n={len(left)} mean={statistics.fmean(left):.2f} ns")
    print(f"class 1 n={len(right)} mean={statistics.fmean(right):.2f} ns")
    print(f"raw Welch t: {raw:.4f}")
    print(f"trimmed Welch t: {trimmed:.4f}")

    if maximum >= 10.0:
        result = "strong timing-class separation"
    elif maximum >= 4.5:
        result = "timing signal requiring investigation"
    else:
        result = "no timing signal detected at this sample size"

    print(f"classification: {result}")


if __name__ == "__main__":
    main()
