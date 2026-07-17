#!/usr/bin/env python3
"""Apply conservative constant-time comparison migrations."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

IMPORT = "use pqc_core::ct::ct_eq_slices;\n"

# These patterns intentionally target validation-shaped comparisons only.
# Public length and parameter comparisons are never rewritten.
MIGRATIONS = (
    re.compile(
        r"(?P<indent>\s*)if\s+(?P<left>[A-Za-z_][A-Za-z0-9_]*(?:\.as_ref\(\))?)\s*"
        r"!=\s*(?P<right>[A-Za-z_][A-Za-z0-9_]*(?:\.as_ref\(\))?)\s*\{"
    ),
    re.compile(
        r"(?P<indent>\s*)if\s+(?P<left>[A-Za-z_][A-Za-z0-9_]*(?:\.as_slice\(\))?)\s*"
        r"!=\s*(?P<right>[A-Za-z_][A-Za-z0-9_]*(?:\.as_slice\(\))?)\s*\{"
    ),
)

SECURITY_HINTS = (
    "ciphertext",
    "challenge",
    "commitment",
    "signature",
    "expected",
    "computed",
    "received",
    "reencrypt",
    "re_encrypted",
    "tag",
)


def ensure_import(text: str) -> str:
    if "use pqc_core::ct::ct_eq_slices;" in text:
        return text

    insertion = 0
    for match in re.finditer(r"^(?:pub\s+)?(?:use|mod)\s+.*?;\n", text, re.MULTILINE):
        insertion = match.end()

    return text[:insertion] + IMPORT + text[insertion:]


def migrate_file(path: Path) -> list[tuple[int, str, str]]:
    text = path.read_text(encoding="utf-8")
    original = text
    changes: list[tuple[int, str, str]] = []

    for pattern in MIGRATIONS:
        cursor = 0
        while True:
            match = pattern.search(text, cursor)
            if match is None:
                break

            left = match.group("left")
            right = match.group("right")

            left_base = left.split(".", 1)[0]
            right_base = right.split(".", 1)[0]

            # Uppercase identifiers are constants, commonly public byte
            # lengths such as CT_BYTES, PK_BYTES, SK_BYTES, or BYTES.
            if (
                left_base.isupper()
                or right_base.isupper()
            ):
                cursor = match.end()
                continue

            context = f"{left} {right}".lower()

            if not any(hint in context for hint in SECURITY_HINTS):
                cursor = match.end()
                continue

            old = match.group(0)
            new = (
                f"{match.group('indent')}if "
                f"ct_eq_slices({left}.as_ref(), {right}.as_ref())"
                f" == pqc_core::ct::CtMask8::FALSE {{"
            )
            line = text.count("\n", 0, match.start()) + 1
            text = text[:match.start()] + new + text[match.end():]
            changes.append((line, old.strip(), new.strip()))
            cursor = match.start() + len(new)

    if text != original:
        text = ensure_import(text)
        path.write_text(text, encoding="utf-8")

    return changes


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path("audit/stage10b6/applied-byte-comparison-migrations.csv"),
    )
    args = parser.parse_args()

    rows: list[dict[str, str]] = []

    for root in (Path("crates/pqc-ml-kem/src"), Path("crates/pqc-ml-dsa/src")):
        if not root.exists():
            continue

        for path in sorted(root.rglob("*.rs")):
            for line, before, after in migrate_file(path):
                rows.append(
                    {
                        "file": str(path),
                        "line": str(line),
                        "before": before,
                        "after": after,
                        "status": "applied",
                    }
                )

    args.ledger.parent.mkdir(parents=True, exist_ok=True)

    with args.ledger.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=("file", "line", "before", "after", "status"),
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"migrations applied: {len(rows)}")
    print(f"ledger: {args.ledger}")


if __name__ == "__main__":
    main()
