#!/usr/bin/env python3
"""Inventory byte-comparison sites for constant-time migration."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

CRATES = (
    "crates/pqc-ml-kem/src",
    "crates/pqc-ml-dsa/src",
)

PATTERNS = (
    ("equality", re.compile(r"(?P<left>[A-Za-z0-9_().&*\[\]]+)\s*==\s*(?P<right>[A-Za-z0-9_().&*\[\]]+)")),
    ("inequality", re.compile(r"(?P<left>[A-Za-z0-9_().&*\[\]]+)\s*!=\s*(?P<right>[A-Za-z0-9_().&*\[\]]+)")),
    ("iterator_all", re.compile(r"\.iter\(\).*\.all\(")),
    ("position", re.compile(r"\.position\(")),
)

SECRET_HINTS = (
    "ciphertext",
    "shared_secret",
    "secret",
    "private",
    "challenge",
    "commitment",
    "signature",
    "expected",
    "reencrypt",
    "re_encrypted",
    "computed",
    "received",
    "tag",
)

PUBLIC_HINTS = (
    ".len()",
    "parameter_set",
    "mode",
    "version",
    "index",
    "count",
    "dimension",
)

FIELDS = (
    "site_id",
    "crate",
    "file",
    "line",
    "kind",
    "source",
    "classification",
    "recommended_primitive",
    "status",
    "rationale",
)


def classify(source: str) -> tuple[str, str, str]:
    lowered = source.lower()

    if any(hint in lowered for hint in PUBLIC_HINTS):
        return (
            "public-structural",
            "none",
            "Public length, parameter, mode, or loop-control comparison.",
        )

    if any(hint in lowered for hint in SECRET_HINTS):
        return (
            "security-relevant",
            "ct_eq_bytes-or-ct_eq_slices",
            "Name and context indicate cryptographic validation data.",
        )

    return (
        "review",
        "manual",
        "Insufficient context for automatic migration.",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("audit/stage10b6/byte-comparison-inventory.csv"),
    )
    args = parser.parse_args()

    rows: list[dict[str, str]] = []
    site = 0

    for root_name in CRATES:
        root = Path(root_name)
        if not root.exists():
            continue

        for path in sorted(root.rglob("*.rs")):
            lines = path.read_text(encoding="utf-8").splitlines()

            for line_number, line in enumerate(lines, start=1):
                stripped = line.strip()

                if stripped.startswith("//"):
                    continue

                for kind, pattern in PATTERNS:
                    if not pattern.search(line):
                        continue

                    classification, primitive, rationale = classify(stripped)
                    site += 1
                    rows.append(
                        {
                            "site_id": f"CTCMP-{site:04}",
                            "crate": root.parts[1],
                            "file": str(path),
                            "line": str(line_number),
                            "kind": kind,
                            "source": stripped,
                            "classification": classification,
                            "recommended_primitive": primitive,
                            "status": (
                                "accepted-public"
                                if classification == "public-structural"
                                else "open"
                            ),
                            "rationale": rationale,
                        }
                    )

    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"comparison sites inventoried: {len(rows)}")
    print(f"inventory: {args.output}")


if __name__ == "__main__":
    main()
