import csv
import json
import math
import statistics
import sys

from collections import defaultdict
from pathlib import Path

root = Path(sys.argv[1])

groups = defaultdict(dict)

with (root / "results.csv").open() as f:
    for row in csv.DictReader(f):
        key = (
            row["level"],
            row["kem"],
            row["operation"],
            row["kdf"],
        )

        trial = int(row["trial"])
        elapsed = int(row["latency_ns"])

        assert trial not in groups[key]
        assert elapsed >= 0

        groups[key][trial] = elapsed / 1000

assert len(groups) == 90

for key, values in groups.items():
    assert set(values) == set(range(10_000)), key


def percentile(values, q):
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    weight = position - lower

    return (
        ordered[lower] * (1 - weight)
        + ordered[upper] * weight
    )


summary = []

for key, trials in sorted(groups.items()):
    level, kem, operation, kdf = key
    values = list(trials.values())

    summary.append({
        "level": level,
        "kem": kem,
        "operation": operation,
        "kdf": kdf,
        "samples": len(values),
        "minimum_us": min(values),
        "mean_us": statistics.mean(values),
        "median_us": statistics.median(values),
        "iqr_us": (
            percentile(values, 0.75)
            - percentile(values, 0.25)
        ),
        "p95_us": percentile(values, 0.95),
        "p99_us": percentile(values, 0.99),
        "maximum_us": max(values),
    })

with (root / "summary.csv").open("w") as f:
    writer = csv.DictWriter(
        f, fieldnames=summary[0].keys()
    )

    writer.writeheader()
    writer.writerows(summary)

comparisons = []

for key in sorted(groups):
    level, kem, operation, kdf = key

    if kdf != "SHA256":
        continue

    sha2 = groups[key]

    sha3 = groups[
        (level, kem, operation, "SHA3-256")
    ]

    median2 = statistics.median(sha2.values())
    median3 = statistics.median(sha3.values())

    assert median2 > 0

    paired_differences = [
        sha3[i] - sha2[i]
        for i in range(10_000)
    ]

    comparisons.append({
        "level": level,
        "kem": kem,
        "operation": operation,
        "sha256_median_us": median2,
        "sha3_median_us": median3,
        "median_difference_us": median3 - median2,
        "paired_difference_median_us":
            statistics.median(paired_differences),
        "sha3_to_sha256_ratio": median3 / median2,
        "sha3_overhead_percent":
            (median3 / median2 - 1) * 100,
    })

assert len(comparisons) == 45

with (root / "comparison.csv").open("w") as f:
    writer = csv.DictWriter(
        f, fieldnames=comparisons[0].keys()
    )

    writer.writeheader()
    writer.writerows(comparisons)

report = {
    "samples_per_configuration": 10_000,
    "warmup_per_configuration": 200,
    "measurement_rows": 900_000,
    "measured_hpke_roundtrips": 120_000,
    "comparison_count": 45,
    "summary": summary,
    "comparisons": comparisons,
    "units": "microseconds",
}

(root / "performance-report.json").write_text(
    json.dumps(report, indent=2) + "\n"
)

print()
print("=== KDF AND KEY-SCHEDULE RESULTS ===")

for row in comparisons:
    if row["level"] == "HPKE":
        continue

    print(
        f'{row["level"]:10s} '
        f'{row["operation"]:16s} '
        f'SHA256={row["sha256_median_us"]:9.3f} us '
        f'SHA3={row["sha3_median_us"]:9.3f} us '
        f'overhead={row["sha3_overhead_percent"]:+8.2f}%'
    )

print()
print("=== COMPLETE HPKE RESULTS ===")

for row in comparisons:
    if row["operation"] != "combined_total":
        continue

    print(
        f'{row["kem"]:22s} '
        f'SHA256={row["sha256_median_us"]:9.3f} us '
        f'SHA3={row["sha3_median_us"]:9.3f} us '
        f'overhead={row["sha3_overhead_percent"]:+8.2f}%'
    )

print()
print("=== CELLULAR-RELEVANT CONFIGURATIONS ===")

for row in comparisons:
    if row["kem"] not in (
        "ML-KEM-768",
        "ML-KEM-768+X25519",
    ):
        continue

    if row["operation"] not in (
        "sender_total",
        "receiver_total",
        "combined_total",
    ):
        continue

    print(
        f'{row["kem"]:22s} '
        f'{row["operation"]:16s} '
        f'SHA256={row["sha256_median_us"]:9.3f} us '
        f'SHA3={row["sha3_median_us"]:9.3f} us '
        f'overhead={row["sha3_overhead_percent"]:+8.2f}%'
    )

print()
print("STATISTICAL_GROUPS=90")
print("COMPARISONS=45")
print("PERFORMANCE_ANALYSIS=PASS")
