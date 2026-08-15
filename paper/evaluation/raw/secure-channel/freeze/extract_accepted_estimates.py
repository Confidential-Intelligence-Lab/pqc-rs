#!/usr/bin/env python3

from pathlib import Path
import csv
import json
import statistics

BASE = Path("paper/evaluation/raw/secure-channel")
FREEZE = BASE / "freeze"
ARCHIVE = BASE / "accepted-runs"

accepted = [
    line.strip()
    for line in (FREEZE / "ACCEPTED_RUNS.txt")
    .read_text(encoding="utf-8")
    .splitlines()
    if line.strip()
]

if len(accepted) != 5:
    raise SystemExit(f"expected 5 accepted runs, found {len(accepted)}")

rows = []

for run_id in accepted:
    run_dir = ARCHIVE / run_id / "criterion" / "secure_channel"

    if not run_dir.is_dir():
        raise SystemExit(f"missing archived Criterion directory: {run_dir}")

    paths = sorted(run_dir.glob("*/*/new/estimates.json"))

    if len(paths) != 24:
        raise SystemExit(
            f"{run_id}: expected 24 estimates.json files, found {len(paths)}"
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

expected_rows = 5 * 24

if len(rows) != expected_rows:
    raise SystemExit(
        f"expected {expected_rows} accepted estimates, found {len(rows)}"
    )

accepted_csv = FREEZE / "accepted_estimates.csv"

with accepted_csv.open(
    "w",
    newline="",
    encoding="utf-8",
) as handle:
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

grouped: dict[tuple[str, str], list[float]] = {}

for row in rows:
    key = (row["operation"], row["profile"])
    grouped.setdefault(key, []).append(float(row["mean_point_ns"]))

if len(grouped) != 24:
    raise SystemExit(
        f"expected 24 operation/profile groups, found {len(grouped)}"
    )

summary_rows = []

for (operation, profile), values in sorted(grouped.items()):
    if len(values) != 5:
        raise SystemExit(
            f"{operation}/{profile}: expected 5 runs, found {len(values)}"
        )

    mean = statistics.fmean(values)
    stdev = statistics.stdev(values)

    summary_rows.append(
        {
            "operation": operation,
            "profile": profile,
            "runs": len(values),
            "cross_run_mean_ns": mean,
            "cross_run_median_ns": statistics.median(values),
            "cross_run_stdev_ns": stdev,
            "cross_run_cv": stdev / mean if mean else 0.0,
            "cross_run_min_ns": min(values),
            "cross_run_max_ns": max(values),
        }
    )

summary_csv = FREEZE / "cross_run_summary.csv"

with summary_csv.open(
    "w",
    newline="",
    encoding="utf-8",
) as handle:
    writer = csv.DictWriter(handle, fieldnames=summary_rows[0].keys())
    writer.writeheader()
    writer.writerows(summary_rows)

print("accepted_runs=5")
print("accepted_estimates=120")
print("summary_rows=24")
print(f"accepted_csv={accepted_csv}")
print(f"summary_csv={summary_csv}")
