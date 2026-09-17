#!/usr/bin/env python3

from __future__ import annotations

import argparse
import re
from pathlib import Path

TARGETS = (
    "audit_slh_shake_prf",
    "audit_slh_shake_prf_msg",
    "audit_slh_sha2_prf",
    "audit_slh_sha2_prf_msg",
    "audit_slh_sha2_128_prf_msg",
)

HEADER = re.compile(r"^([_A-Za-z.$][-_A-Za-z0-9.$]*)\s*:$")
INSTRUCTION = re.compile(r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z.][a-zA-Z0-9.]*)\b")

CONDITIONAL_BRANCHES = {
    "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
    "b.hi", "b.hs", "b.lo", "b.ls", "b.mi", "b.pl",
    "cbz", "cbnz", "tbz", "tbnz",
}

CONDITIONAL_SELECTS = {"csel", "csinc", "csinv", "csneg"}
DIVISIONS = {"sdiv", "udiv"}
TABLE_LOOKUPS = {"tbl", "tbx"}

def extract(text: str) -> dict[str, list[str]]:
    found = {target: [] for target in TARGETS}
    current = None

    for line in text.splitlines():
        match = HEADER.match(line)
        if match:
            symbol = match.group(1)
            current = next(
                (
                    target
                    for target in sorted(TARGETS, key=len, reverse=True)
                    if target in symbol
                ),
                None,
            )

        if current is not None:
            found[current].append(line)

    return found

def classify(lines: list[str]) -> dict[str, list[str]]:
    out = {
        "conditional_branches": [],
        "conditional_selects": [],
        "divisions": [],
        "table_lookups": [],
        "indexed_memory_candidates": [],
    }

    for line in lines:
        match = INSTRUCTION.match(line)
        if not match:
            continue

        mnemonic = match.group(1).lower()

        if mnemonic in CONDITIONAL_BRANCHES:
            out["conditional_branches"].append(line.strip())

        if mnemonic in CONDITIONAL_SELECTS:
            out["conditional_selects"].append(line.strip())

        if mnemonic in DIVISIONS:
            out["divisions"].append(line.strip())

        if mnemonic in TABLE_LOOKUPS:
            out["table_lookups"].append(line.strip())

        lowered = line.lower()
        if "[" in lowered and any(
            token in lowered for token in (", x", ", w", "lsl", "uxtw", "sxtw")
        ):
            out["indexed_memory_candidates"].append(line.strip())

    return out

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("objdump", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    text = args.objdump.read_text(encoding="utf-8", errors="replace")
    functions = extract(text)

    summary = args.output_dir / "audit-summary.md"
    flagged = args.output_dir / "flagged-instructions.md"

    with summary.open("w", encoding="utf-8") as stream:
        print("# SLH-DSA S6 optimized machine-code audit", file=stream)
        print(file=stream)

        for target, lines in functions.items():
            result = classify(lines)

            print(f"## `{target}`", file=stream)
            print(f"- recovered lines: {len(lines)}", file=stream)

            for category, values in result.items():
                print(f"- {category}: {len(values)}", file=stream)

            print(
                "- status: recovered" if lines else "- status: wrapper symbol not recovered",
                file=stream,
            )
            print(file=stream)

    with flagged.open("w", encoding="utf-8") as stream:
        print("# SLH-DSA S6 flagged machine-code candidates", file=stream)
        print(file=stream)

        for target, lines in functions.items():
            print(f"## `{target}`", file=stream)
            result = classify(lines)

            for category, values in result.items():
                print(f"### {category}", file=stream)
                if values:
                    for value in values:
                        print(f"- `{value}`", file=stream)
                else:
                    print("- none", file=stream)
                print(file=stream)

if __name__ == "__main__":
    main()
