from pathlib import Path
import csv
import json
import statistics

BASE = Path("paper/evaluation/raw/secure-channel")
FREEZE = BASE / "freeze"

accepted = [
    line.strip()
    for line in (FREEZE / "ACCEPTED_RUNS.txt").read_text(encoding="utf-8").splitlines()
    if line.strip()
]

rows = []

for run_id in accepted:
    run_dir = BASE / "runs" / run_id / "criterion" / "secure_channel"

    for path in sorted(run_dir.glob("*/*/new/estimates.json")):
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

expected = len(accepted) * 24
if len(rows) != expected:
    raise SystemExit(f"expected {expected} rows, found {len(rows)}")

with (FREEZE / "accepted_estimates.csv").open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

grouped = {}
for row in rows:
    key = (row["operation"], row["profile"])
    grouped.setdefault(key, []).append(float(row["mean_point_ns"]))

summary = []

for (operation, profile), values in sorted(grouped.items()):
    if len(values) != len(accepted):
        raise SystemExit(
            f"{operation}/{profile}: expected {len(accepted)} runs, found {len(values)}"
        )

    mean = statistics.fmean(values)
    stdev = statistics.stdev(values)

    summary.append(
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

with (FREEZE / "cross_run_summary.csv").open(
    "w", newline="", encoding="utf-8"
) as handle:
    writer = csv.DictWriter(handle, fieldnames=summary[0].keys())
    writer.writeheader()
    writer.writerows(summary)

print(f"accepted_runs={len(accepted)}")
print(f"accepted_estimates={len(rows)}")
print(f"summary_rows={len(summary)}")
