#!/usr/bin/env python3
"""Record mismatch-position timing evidence without hard-gating hosted runners."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any


LABELS = {
    0: "first-byte mismatch",
    1: "middle-byte mismatch",
    2: "last-byte mismatch",
    3: "equal",
}
COMPARISONS = ((0, 1), (0, 2), (1, 2), (0, 3), (1, 3), (2, 3))


def welch_t(left: list[float], right: list[float]) -> float:
    denominator = math.sqrt(
        statistics.variance(left) / len(left)
        + statistics.variance(right) / len(right)
    )
    if denominator == 0.0:
        return 0.0
    return (statistics.fmean(left) - statistics.fmean(right)) / denominator


def analyze(csv_path: Path, threshold: float) -> dict[str, Any]:
    classes: dict[int, list[float]] = defaultdict(list)
    with csv_path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["sample", "class", "nanoseconds"]:
            raise ValueError("unexpected timing CSV header")
        for row in reader:
            class_id = int(row["class"])
            nanoseconds = float(row["nanoseconds"])
            if class_id not in LABELS:
                raise ValueError(f"unexpected timing class: {class_id}")
            if not math.isfinite(nanoseconds) or nanoseconds < 0:
                raise ValueError("timing values must be finite and non-negative")
            classes[class_id].append(nanoseconds)

    missing = sorted(set(LABELS) - set(classes))
    if missing:
        raise ValueError(f"missing timing classes: {missing}")
    if any(len(values) < 2 for values in classes.values()):
        raise ValueError("each timing class requires at least two observations")

    summaries = []
    for class_id in sorted(LABELS):
        values = classes[class_id]
        summaries.append({
            "class": class_id,
            "label": LABELS[class_id],
            "samples": len(values),
            "mean_nanoseconds": statistics.fmean(values),
            "median_nanoseconds": statistics.median(values),
            "population_stddev_nanoseconds": statistics.pstdev(values),
            "minimum_nanoseconds": min(values),
            "maximum_nanoseconds": max(values),
        })

    comparisons = []
    maximum = 0.0
    for left, right in COMPARISONS:
        statistic = welch_t(classes[left], classes[right])
        maximum = max(maximum, abs(statistic))
        comparisons.append({
            "left_class": left,
            "right_class": right,
            "left_label": LABELS[left],
            "right_label": LABELS[right],
            "welch_t": statistic,
        })

    return {
        "schema_version": 1,
        "gating": False,
        "threshold_absolute_welch_t": threshold,
        "maximum_absolute_welch_t": maximum,
        "classification": (
            "signal-detected" if maximum >= threshold else "no-signal-detected"
        ),
        "statement": (
            "Hosted-runner timing is architecture-specific regression evidence. "
            "A threshold crossing is retained for review but does not fail Stage 10B-5."
        ),
        "classes": summaries,
        "comparisons": comparisons,
    }


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Stage 10B-5 timing evidence",
        "",
        "This hosted-runner result is evidence, not a proof of constant-time execution.",
        "The timing threshold is explicitly non-gating.",
        "",
        f"Classification: **{report['classification']}**",
        "",
        f"Maximum absolute Welch t: `{report['maximum_absolute_welch_t']:.6f}`",
        "",
        "| Class | Samples | Mean ns | Median ns | Population stddev ns |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in report["classes"]:
        lines.append(
            f"| {item['label']} | {item['samples']} | "
            f"{item['mean_nanoseconds']:.6f} | "
            f"{item['median_nanoseconds']:.6f} | "
            f"{item['population_stddev_nanoseconds']:.6f} |"
        )
    lines.extend(["", "## Pairwise comparisons", ""])
    for item in report["comparisons"]:
        lines.append(
            f"- {item['left_label']} vs {item['right_label']}: "
            f"`t={item['welch_t']:.6f}`"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = analyze(args.csv, args.threshold)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.output.with_suffix(".md").write_text(markdown_report(report), encoding="utf-8")
    print(f"timing classification={report['classification']}")
    print(f"timing gating={str(report['gating']).lower()}")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
