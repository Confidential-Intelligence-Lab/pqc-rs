#!/usr/bin/env python3

from pathlib import Path
import csv
import json
import statistics

BASE = Path("paper/evaluation/raw/hpke-composition")
FREEZE = BASE / "freeze"
RUNS = BASE / "accepted-runs"

PURE = "MLKEM768"
HYBRID = "MLKEM768-X25519"

accepted = [
    line.strip()
    for line in (FREEZE / "ACCEPTED_RUNS.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
]

if len(accepted) != 5:
    raise SystemExit(f"expected 5 accepted runs, found {len(accepted)}")

rows = []

for run_id in accepted:
    root = RUNS / run_id / "criterion" / "hpke_composition"

    paths = sorted(root.glob("*/*/new/estimates.json"))

    if len(paths) != 8:
        raise SystemExit(
            f"{run_id}: expected 8 estimates.json files, found {len(paths)}"
        )

    for path in paths:
        operation = path.parents[2].name
        profile = path.parents[1].name

        data = json.loads(path.read_text(encoding="utf-8"))
        mean = data["mean"]
        median = data["median"]

        rows.append(
            {
                "run_id": run_id,
                "operation": operation,
                "profile": profile,
                "mean_point_ns": mean["point_estimate"],
                "mean_ci_low_ns": mean["confidence_interval"]["lower_bound"],
                "mean_ci_high_ns": mean["confidence_interval"]["upper_bound"],
                "median_point_ns": median["point_estimate"],
                "median_ci_low_ns": median["confidence_interval"]["lower_bound"],
                "median_ci_high_ns": median["confidence_interval"]["upper_bound"],
            }
        )

if len(rows) != 40:
    raise SystemExit(f"expected 40 accepted estimates, found {len(rows)}")

raw_csv = FREEZE / "accepted_estimates.csv"

with raw_csv.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

by_run = {}

for row in rows:
    key = (row["run_id"], row["operation"])
    by_run.setdefault(key, {})[row["profile"]] = float(row["mean_point_ns"])

operations = sorted({row["operation"] for row in rows})

comparison_rows = []

for operation in operations:
    pure_values = []
    hybrid_values = []
    deltas = []
    ratios = []
    overheads = []

    for run_id in accepted:
        pair = by_run[(run_id, operation)]

        if PURE not in pair or HYBRID not in pair:
            raise SystemExit(f"{run_id}/{operation}: incomplete profile pair")

        pure = pair[PURE]
        hybrid = pair[HYBRID]

        delta = hybrid - pure
        ratio = hybrid / pure
        overhead = (ratio - 1.0) * 100.0

        pure_values.append(pure)
        hybrid_values.append(hybrid)
        deltas.append(delta)
        ratios.append(ratio)
        overheads.append(overhead)

    comparison_rows.append(
        {
            "operation": operation,
            "runs": len(accepted),
            "pure_mean_ns": statistics.fmean(pure_values),
            "pure_stdev_ns": statistics.stdev(pure_values),
            "hybrid_mean_ns": statistics.fmean(hybrid_values),
            "hybrid_stdev_ns": statistics.stdev(hybrid_values),
            "delta_mean_ns": statistics.fmean(deltas),
            "delta_stdev_ns": statistics.stdev(deltas),
            "ratio_mean": statistics.fmean(ratios),
            "ratio_stdev": statistics.stdev(ratios),
            "overhead_mean_percent": statistics.fmean(overheads),
            "overhead_stdev_percent": statistics.stdev(overheads),
        }
    )

summary_csv = FREEZE / "composition_summary.csv"

with summary_csv.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=comparison_rows[0].keys())
    writer.writeheader()
    writer.writerows(comparison_rows)

print(f"accepted_runs={len(accepted)}")
print(f"accepted_estimates={len(rows)}")
print(f"operations={len(comparison_rows)}")
print(f"raw_csv={raw_csv}")
print(f"summary_csv={summary_csv}")
