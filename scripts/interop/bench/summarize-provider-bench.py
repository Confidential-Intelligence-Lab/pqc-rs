#!/usr/bin/env python3

from __future__ import annotations

import json
import random
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "target" / "camera-ready-provider-bench"

ROUNDS = 10_000
SEED = 1

PROVIDER_DIRS = [
    ("pqc-rs", RESULTS / "pqc-rs"),
    ("liboqs", RESULTS / "liboqs"),
    ("openssl", RESULTS / "openssl"),
    ("wolfssl", RESULTS / "wolfssl"),
    ("awslc", RESULTS / "awslc"),
    ("bouncycastle", RESULTS / "bouncycastle"),
    ("liboqs", RESULTS / "liboqs-dsa"),
    ("openssl", RESULTS / "openssl-dsa"),
]

PROVIDER_ORDER = {
    "pqc-rs": 0,
    "liboqs": 1,
    "openssl": 2,
    "wolfssl": 3,
    "awslc": 4,
    "bouncycastle": 5,
}

PROVIDER_LABEL = {
    "pqc-rs": "PQC-rs",
    "liboqs": "liboqs",
    "openssl": "OpenSSL",
    "wolfssl": "wolfSSL",
    "awslc": "AWS-LC",
    "bouncycastle": "Bouncy Castle",
}

OPERATION_ORDER = {
    ("ML-KEM-768", "kem-keygen"): 0,
    ("ML-KEM-768", "kem-encaps"): 1,
    ("ML-KEM-768", "kem-decaps"): 2,
    ("ML-DSA-65", "dsa-keygen"): 3,
    ("ML-DSA-65", "dsa-sign"): 4,
    ("ML-DSA-65", "dsa-verify"): 5,
}

OPERATION_LABEL = {
    ("ML-KEM-768", "kem-keygen"): "ML-KEM-768 KeyGen",
    ("ML-KEM-768", "kem-encaps"): "ML-KEM-768 Encaps",
    ("ML-KEM-768", "kem-decaps"): "ML-KEM-768 Decaps",
    ("ML-DSA-65", "dsa-keygen"): "ML-DSA-65 KeyGen",
    ("ML-DSA-65", "dsa-sign"): "ML-DSA-65 Sign",
    ("ML-DSA-65", "dsa-verify"): "ML-DSA-65 Verify",
}


def bootstrap_median_ci(
    xs: list[float],
    *,
    rounds: int = ROUNDS,
    seed: int = SEED,
) -> tuple[float, float, float]:
    rng = random.Random(seed)
    n = len(xs)
    boots: list[float] = []

    for _ in range(rounds):
        sample = [xs[rng.randrange(n)] for _ in range(n)]
        boots.append(statistics.median(sample))

    boots.sort()

    lo = boots[int(0.025 * rounds)]
    hi = boots[int(0.975 * rounds)]

    return statistics.median(xs), lo, hi


def load_records() -> list[dict]:
    records: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    for expected_provider, directory in PROVIDER_DIRS:
        if not directory.exists():
            continue

        for path in sorted(directory.glob("*.json")):
            data = json.loads(path.read_text())

            provider = data["provider"]
            primitive = data["primitive"]
            operation = data["operation"]

            if provider != expected_provider:
                raise RuntimeError(
                    f"{path}: provider={provider!r}, "
                    f"expected {expected_provider!r}"
                )

            key = (provider, primitive, operation)
            if key in seen:
                raise RuntimeError(
                    f"duplicate benchmark result for {key}"
                )
            seen.add(key)

            samples = list(data["sample_ns"])

            if len(samples) != 100:
                raise RuntimeError(
                    f"{path}: expected 100 samples, "
                    f"found {len(samples)}"
                )

            median_ns, lo_ns, hi_ns = bootstrap_median_ci(samples)

            records.append(
                {
                    "provider": provider,
                    "primitive": primitive,
                    "operation": operation,
                    "samples": len(samples),
                    "iterations_per_sample":
                        data["iterations_per_sample"],
                    "median_us": median_ns / 1000.0,
                    "ci_lo_us": lo_ns / 1000.0,
                    "ci_hi_us": hi_ns / 1000.0,
                }
            )

    records.sort(
        key=lambda r: (
            OPERATION_ORDER[
                (r["primitive"], r["operation"])
            ],
            PROVIDER_ORDER[r["provider"]],
        )
    )

    return records


def write_json(records: list[dict]) -> None:
    payload = {
        "bootstrap_rounds": ROUNDS,
        "random_seed": SEED,
        "statistic": "median",
        "confidence_interval": "bootstrap 95%",
        "records": records,
    }

    (RESULTS / "summary.json").write_text(
        json.dumps(payload, indent=2) + "\n"
    )


def write_markdown(records: list[dict]) -> None:
    by_operation: dict[tuple[str, str], dict[str, dict]] = {}

    for record in records:
        op = (
            record["primitive"],
            record["operation"],
        )
        by_operation.setdefault(op, {})[
            record["provider"]
        ] = record

    providers = [
        "pqc-rs",
        "liboqs",
        "openssl",
        "wolfssl",
        "awslc",
        "bouncycastle",
    ]

    lines = [
        "# Cross-Provider Performance Summary",
        "",
        "All values are median latency in microseconds. "
        "Each measurement contains 100 statistical samples. "
        f"Confidence intervals use {ROUNDS:,} bootstrap "
        f"resamples with random seed {SEED}.",
        "",
        "| Operation | "
        + " | ".join(PROVIDER_LABEL[p] for p in providers)
        + " |",
        "|---|" + "|".join("---:" for _ in providers) + "|",
    ]

    for op in sorted(
        by_operation,
        key=lambda x: OPERATION_ORDER[x],
    ):
        cells = []

        for provider in providers:
            r = by_operation[op][provider]

            cells.append(
                f"{r['median_us']:.3f} "
                f"[{r['ci_lo_us']:.3f}, "
                f"{r['ci_hi_us']:.3f}]"
            )

        lines.append(
            "| "
            + OPERATION_LABEL[op]
            + " | "
            + " | ".join(cells)
            + " |"
        )

    lines.extend(
        [
            "",
            "## Method",
            "",
            "- 100 samples per provider-operation pair.",
            "- Per-sample inner-loop calibration targets "
            "approximately 5 ms or more.",
            "- Native providers use in-process monotonic timing.",
            "- Bouncy Castle uses a persistent JVM with per-operation "
            "warm-up before measurement.",
            "- Reported intervals are bootstrap 95% confidence "
            "intervals for the median.",
            "- AWS-LC ML-DSA signing uses the provider's ordinary "
            "randomized public signing path because explicit "
            "caller-supplied signing randomness is not exposed by "
            "the tested public API.",
            "",
        ]
    )

    (RESULTS / "SUMMARY.md").write_text(
        "\n".join(lines)
    )


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)

    records = load_records()

    expected = 6 * 6
    if len(records) != expected:
        raise RuntimeError(
            f"expected {expected} provider-operation results, "
            f"found {len(records)}"
        )

    write_json(records)
    write_markdown(records)

    print(f"records={len(records)}")
    print(f"summary={RESULTS / 'SUMMARY.md'}")
    print(f"json={RESULTS / 'summary.json'}")


if __name__ == "__main__":
    main()
