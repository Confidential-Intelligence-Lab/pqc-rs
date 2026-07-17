#!/usr/bin/env python3
"""Inventory conditional assignment and selection candidates."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

ROOTS = (
    Path("crates/pqc-ml-kem/src"),
    Path("crates/pqc-ml-dsa/src"),
)

IF_RE = re.compile(r"^\s*if\s+(?P<condition>.+?)\s*\{\s*$")
ASSIGN_RE = re.compile(
    r"^\s*(?P<destination>[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*"
    r"=\s*(?P<source>[^=].*?);\s*$"
)
SWAP_RE = re.compile(r"\b(?:swap|mem::swap|core::mem::swap)\s*\(")
TERNARY_HINT_RE = re.compile(r"^\s*let\s+.+?=\s*if\s+.+?\{")

SECRET_HINTS = (
    "secret",
    "private",
    "shared",
    "message",
    "ciphertext",
    "failure",
    "valid",
    "invalid",
    "mask",
    "choice",
    "select",
    "challenge",
    "coefficient",
    "decaps",
    "decrypt",
    "reject",
)

PUBLIC_HINTS = (
    ".len()",
    "parameter",
    "index",
    "count",
    "dimension",
    "mode",
    "version",
    "tau",
    "omega",
)

FIELDS = (
    "site_id",
    "crate",
    "file",
    "line",
    "kind",
    "condition",
    "source",
    "classification",
    "recommended_primitive",
    "status",
    "rationale",
)


def classify(condition: str, source: str) -> tuple[str, str, str]:
    context = f"{condition} {source}".lower()

    if any(hint in context for hint in PUBLIC_HINTS):
        return (
            "public-structural",
            "none",
            "Condition appears to use public length, parameter, or loop state.",
        )

    if any(hint in context for hint in SECRET_HINTS):
        return (
            "security-relevant",
            "ct-select-or-ct-assign",
            "Condition or assigned value appears secret-bearing or validation-sensitive.",
        )

    return (
        "review",
        "manual",
        "Insufficient context for automatic classification.",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "audit/stage10b6/conditional-assignment-inventory.csv"
        ),
    )
    args = parser.parse_args()

    rows: list[dict[str, str]] = []
    site = 0

    for root in ROOTS:
        if not root.exists():
            continue

        for path in sorted(root.rglob("*.rs")):
            lines = path.read_text(encoding="utf-8").splitlines()
            active_condition: str | None = None
            active_depth = 0

            for line_number, line in enumerate(lines, start=1):
                stripped = line.strip()

                if stripped.startswith("//"):
                    continue

                if_match = IF_RE.match(line)
                if if_match:
                    active_condition = if_match.group("condition")
                    active_depth = line.count("{") - line.count("}")

                elif active_condition is not None:
                    active_depth += line.count("{") - line.count("}")

                kind = None
                condition = active_condition or ""

                if active_condition is not None and ASSIGN_RE.match(line):
                    kind = "conditional-assignment"
                elif SWAP_RE.search(line):
                    kind = "swap"
                elif TERNARY_HINT_RE.search(line):
                    kind = "if-expression-selection"
                    condition = stripped

                if kind is not None:
                    classification, primitive, rationale = classify(
                        condition,
                        stripped,
                    )
                    site += 1
                    rows.append(
                        {
                            "site_id": f"CTSEL-{site:04}",
                            "crate": root.parts[1],
                            "file": str(path),
                            "line": str(line_number),
                            "kind": kind,
                            "condition": condition,
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

                if active_condition is not None and active_depth <= 0:
                    active_condition = None
                    active_depth = 0

    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"conditional sites inventoried: {len(rows)}")
    print(f"inventory: {args.output}")


if __name__ == "__main__":
    main()
