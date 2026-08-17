#!/usr/bin/env python3

from __future__ import annotations

import csv
import hashlib
import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parents[3]

E2_INPUT = (
    ROOT
    / "paper/evaluation/raw/secure-channel/freeze/cross_run_summary.csv"
)

E3_INPUT = (
    ROOT
    / "paper/evaluation/raw/hpke-composition/freeze/composition_summary.csv"
)

OUT = ROOT / "paper/evaluation/derived"
FIGURES = OUT / "figures"

E2_CSV = OUT / "secure-channel-summary.csv"
E3_CSV = OUT / "hpke-composition-summary.csv"

E2_TEX = OUT / "secure-channel-summary.tex"
E3_TEX = OUT / "hpke-composition-summary.tex"

E3_FIGURE = FIGURES / "hpke-composition-overhead.pdf"

E2_OPERATIONS = [
    "activate_sender",
    "activate_receiver",
    "establish_channel",
    "seal_1k",
    "open_1k",
]

E2_PROFILES = [
    "MLKEM768",
    "MLKEM768-X25519",
    "MLKEM1024",
]

E3_OPERATIONS = [
    "setup_sender",
    "setup_receiver",
    "seal_1k",
    "open_1k",
]


def fail(message: str) -> None:
    raise SystemExit(f"E8: FAIL - {message}")


def finite(value: str, label: str) -> float:
    try:
        number = float(value)
    except ValueError:
        fail(f"non-numeric value for {label}: {value!r}")

    if not math.isfinite(number):
        fail(f"non-finite value for {label}: {value!r}")

    return number


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file():
        fail(f"missing frozen input: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames is None:
            fail(f"missing CSV header: {path}")

        return list(reader.fieldnames), list(reader)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_csv(
    path: Path,
    header: list[str],
    rows: list[list[str]],
) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def validate_e2(
    header: list[str],
    rows: list[dict[str, str]],
) -> dict[tuple[str, str], dict[str, str]]:
    required = {
        "operation",
        "profile",
        "runs",
        "cross_run_mean_ns",
        "cross_run_median_ns",
        "cross_run_stdev_ns",
        "cross_run_cv",
        "cross_run_min_ns",
        "cross_run_max_ns",
    }

    missing = required.difference(header)

    if missing:
        fail(f"E2 missing columns: {sorted(missing)}")

    if len(rows) != 24:
        fail(f"E2 row count={len(rows)}, expected 24")

    indexed: dict[tuple[str, str], dict[str, str]] = {}

    for row in rows:
        key = (row["operation"], row["profile"])

        if key in indexed:
            fail(f"duplicate E2 row: {key}")

        finite(
            row["cross_run_mean_ns"],
            f"E2 {key} cross_run_mean_ns",
        )

        indexed[key] = row

    for operation in E2_OPERATIONS:
        for profile in E2_PROFILES:
            if (operation, profile) not in indexed:
                fail(f"missing E2 row: {(operation, profile)}")

    for operation in (
        "negotiation",
        "profile_resolution",
        "binding",
    ):
        for profile in E2_PROFILES:
            if (operation, profile) not in indexed:
                fail(f"missing E2 agility row: {(operation, profile)}")

    print("E2 FROZEN INPUT VALIDATION: PASS")

    return indexed


def validate_e3(
    header: list[str],
    rows: list[dict[str, str]],
) -> dict[str, dict[str, str]]:
    required = {
        "operation",
        "runs",
        "pure_mean_ns",
        "pure_stdev_ns",
        "hybrid_mean_ns",
        "hybrid_stdev_ns",
        "delta_mean_ns",
        "delta_stdev_ns",
        "ratio_mean",
        "ratio_stdev",
        "overhead_mean_percent",
        "overhead_stdev_percent",
    }

    missing = required.difference(header)

    if missing:
        fail(f"E3 missing columns: {sorted(missing)}")

    if len(rows) != 4:
        fail(f"E3 row count={len(rows)}, expected 4")

    indexed: dict[str, dict[str, str]] = {}

    for row in rows:
        operation = row["operation"]

        if operation in indexed:
            fail(f"duplicate E3 operation: {operation}")

        for field in (
            "pure_mean_ns",
            "hybrid_mean_ns",
            "delta_mean_ns",
            "ratio_mean",
            "overhead_mean_percent",
        ):
            finite(
                row[field],
                f"E3 {operation} {field}",
            )

        indexed[operation] = row

    for operation in E3_OPERATIONS:
        if operation not in indexed:
            fail(f"missing E3 operation: {operation}")

    print("E3 FROZEN INPUT VALIDATION: PASS")

    return indexed


def generate_e2(
    indexed: dict[tuple[str, str], dict[str, str]],
) -> None:
    rows: list[list[str]] = []

    for operation in E2_OPERATIONS:
        row = [operation]

        for profile in E2_PROFILES:
            mean_ns = finite(
                indexed[(operation, profile)]["cross_run_mean_ns"],
                f"E2 {operation}/{profile}",
            )

            row.append(f"{mean_ns / 1000.0:.3f}")

        rows.append(row)

    write_csv(
        E2_CSV,
        [
            "operation",
            "MLKEM768_mean_us",
            "MLKEM768-X25519_mean_us",
            "MLKEM1024_mean_us",
        ],
        rows,
    )

    labels = {
        "activate_sender": "Sender activation",
        "activate_receiver": "Receiver activation",
        "establish_channel": "Channel establishment",
        "seal_1k": "Seal 1 KiB",
        "open_1k": "Open 1 KiB",
    }

    lines = [
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"Operation & ML-KEM-768 & ML-KEM-768+X25519 & ML-KEM-1024 \\",
        r"\midrule",
    ]

    for row in rows:
        lines.append(
            f"{labels[row[0]]} & {row[1]} & {row[2]} & {row[3]} \\\\"
        )

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        "",
    ]

    E2_TEX.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def generate_e3(
    indexed: dict[str, dict[str, str]],
) -> None:
    rows: list[list[str]] = []

    for operation in E3_OPERATIONS:
        row = indexed[operation]

        pure = finite(
            row["pure_mean_ns"],
            f"E3 {operation} pure",
        ) / 1000.0

        hybrid = finite(
            row["hybrid_mean_ns"],
            f"E3 {operation} hybrid",
        ) / 1000.0

        delta = finite(
            row["delta_mean_ns"],
            f"E3 {operation} delta",
        ) / 1000.0

        overhead = finite(
            row["overhead_mean_percent"],
            f"E3 {operation} overhead",
        )

        rows.append(
            [
                operation,
                f"{pure:.3f}",
                f"{hybrid:.3f}",
                f"{delta:.3f}",
                f"{overhead:.2f}",
            ]
        )

    write_csv(
        E3_CSV,
        [
            "operation",
            "pure_mean_us",
            "hybrid_mean_us",
            "delta_mean_us",
            "overhead_mean_percent",
        ],
        rows,
    )

    labels = {
        "setup_sender": "Sender setup",
        "setup_receiver": "Receiver setup",
        "seal_1k": "Seal 1 KiB",
        "open_1k": "Open 1 KiB",
    }

    lines = [
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Operation & Pure ($\mu$s) & Hybrid ($\mu$s) & $\Delta$ ($\mu$s) & Overhead \\",
        r"\midrule",
    ]

    for row in rows:
        overhead = float(row[4])
        sign = "+" if overhead > 0 else ""

        lines.append(
            f"{labels[row[0]]} & {row[1]} & {row[2]} & "
            f"{row[3]} & {sign}{row[4]}\\% \\\\"
        )

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        "",
    ]

    E3_TEX.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def generate_figure(
    indexed: dict[str, dict[str, str]],
) -> None:
    operations = E3_OPERATIONS

    labels = [
        "Sender setup",
        "Receiver setup",
        "Seal 1 KiB",
        "Open 1 KiB",
    ]

    ratios = [
        finite(
            indexed[operation]["ratio_mean"],
            f"E3 {operation} ratio",
        )
        for operation in operations
    ]

    figure, axis = plt.subplots(
        figsize=(6.4, 3.5),
    )

    positions = list(range(len(operations)))

    axis.bar(
        positions,
        ratios,
    )

    axis.axhline(
        1.0,
        linewidth=1.0,
    )

    axis.set_xticks(positions)

    axis.set_xticklabels(
        labels,
        rotation=20,
        ha="right",
    )

    axis.set_ylabel("Hybrid / pure mean")

    axis.set_title(
        "HPKE composition cost relative to ML-KEM-768"
    )

    axis.set_ylim(
        min(0.95, min(ratios) - 0.02),
        max(1.50, max(ratios) + 0.05),
    )

    for position, ratio in zip(
        positions,
        ratios,
        strict=True,
    ):
        axis.text(
            position,
            ratio + 0.012,
            f"{ratio:.3f}x",
            ha="center",
            va="bottom",
            fontsize=8,
        )

    figure.tight_layout()

    figure.savefig(
        E3_FIGURE,
        format="pdf",
        bbox_inches="tight",
        metadata={
            "Title": "HPKE composition overhead",
            "Author": "PQC-Forge evaluation",
            "Creator": "generate_paper_results.py",
            "Producer": "matplotlib",
            "CreationDate": None,
            "ModDate": None,
        },
    )

    plt.close(figure)


def verify_outputs() -> None:
    required = [
        E2_CSV,
        E3_CSV,
        E2_TEX,
        E3_TEX,
        E3_FIGURE,
    ]

    for path in required:
        if not path.is_file():
            fail(f"missing output: {path}")

        if path.stat().st_size == 0:
            fail(f"empty output: {path}")

    with E2_CSV.open(
        newline="",
        encoding="utf-8",
    ) as handle:
        rows = list(csv.DictReader(handle))

        if len(rows) != 5:
            fail(
                f"E2 derived row count={len(rows)}, expected 5"
            )

    with E3_CSV.open(
        newline="",
        encoding="utf-8",
    ) as handle:
        rows = list(csv.DictReader(handle))

        if len(rows) != 4:
            fail(
                f"E3 derived row count={len(rows)}, expected 4"
            )


def generate_all() -> dict[Path, str]:
    OUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    FIGURES.mkdir(
        parents=True,
        exist_ok=True,
    )

    e2_header, e2_rows = read_csv(E2_INPUT)
    e3_header, e3_rows = read_csv(E3_INPUT)

    e2 = validate_e2(
        e2_header,
        e2_rows,
    )

    e3 = validate_e3(
        e3_header,
        e3_rows,
    )

    generate_e2(e2)
    generate_e3(e3)

    print("PAPER TABLE GENERATION: PASS")

    generate_figure(e3)

    print("FIGURE GENERATION: PASS")

    verify_outputs()

    return {
        path: sha256(path)
        for path in [
            E2_CSV,
            E3_CSV,
            E2_TEX,
            E3_TEX,
            E3_FIGURE,
        ]
    }


def main() -> None:
    first = generate_all()
    second = generate_all()

    if first != second:
        fail(
            "derived artifacts changed across immediate regeneration"
        )

    print(
        "DETERMINISTIC REGENERATION: PASS"
    )

    print()

    print(
        "E8 PAPER RESULTS DERIVATION: PASS"
    )


if __name__ == "__main__":
    main()
