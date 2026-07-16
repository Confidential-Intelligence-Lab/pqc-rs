#!/usr/bin/env python3
"""Extract audit wrapper machine code and classify instruction families."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


TARGETS = (
    "audit_multiply_challenge",
    "audit_sample_eta",
    "audit_sample_ball",
    "audit_rounding",
    "audit_encoding",
    "audit_sign_verify",
)

ELF_HEADER = re.compile(
    r"^[0-9a-fA-F]+\s+<(.+)>:$"
)
MACHO_HEADER = re.compile(
    r"^([_A-Za-z.$][-_A-Za-z0-9.$]*)\s*:$"
)
INSTRUCTION = re.compile(r"^\s*[0-9a-fA-F]+:\s+([a-zA-Z.][a-zA-Z0-9.]*)\b")

CONDITIONAL_BRANCHES = {
    "b.eq", "b.ne", "b.lt", "b.le", "b.gt", "b.ge",
    "b.hi", "b.hs", "b.lo", "b.ls", "b.mi", "b.pl",
    "cbz", "cbnz", "tbz", "tbnz",
}
CONDITIONAL_SELECTS = {"csel", "csinc", "csinv", "csneg"}
DIVISIONS = {"sdiv", "udiv"}
TABLE_LOOKUPS = {"tbl", "tbx"}
VECTOR_PREFIXES = (
    "ld1", "st1", "addv", "mul", "mla", "mls", "umull", "smull",
)


def extract_functions(text: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {
        target: [] for target in TARGETS
    }
    current: str | None = None

    for line in text.splitlines():
        elf_match = ELF_HEADER.match(line)
        macho_match = MACHO_HEADER.match(line)

        if elf_match is not None or macho_match is not None:
            symbol = (
                elf_match.group(1)
                if elf_match is not None
                else macho_match.group(1)
            )

            current = next(
                (
                    target
                    for target in TARGETS
                    if target in symbol
                ),
                None,
            )

        if current is not None:
            found[current].append(line)

    return found

def classify(lines: list[str]) -> dict[str, list[str]]:
    result = {
        "conditional_branches": [],
        "conditional_selects": [],
        "divisions": [],
        "table_lookups": [],
        "vector_candidates": [],
        "indexed_memory_candidates": [],
    }

    for line in lines:
        match = INSTRUCTION.match(line)
        if not match:
            continue

        mnemonic = match.group(1).lower()

        if mnemonic in CONDITIONAL_BRANCHES:
            result["conditional_branches"].append(line.strip())
        if mnemonic in CONDITIONAL_SELECTS:
            result["conditional_selects"].append(line.strip())
        if mnemonic in DIVISIONS:
            result["divisions"].append(line.strip())
        if mnemonic in TABLE_LOOKUPS:
            result["table_lookups"].append(line.strip())
        if mnemonic.startswith(VECTOR_PREFIXES):
            result["vector_candidates"].append(line.strip())

        lowered = line.lower()
        if "[" in lowered and any(
            token in lowered
            for token in (", x", ", w", "lsl", "uxtw", "sxtw")
        ):
            result["indexed_memory_candidates"].append(line.strip())

    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("objdump", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    text = args.objdump.read_text(encoding="utf-8", errors="replace")
    functions = extract_functions(text)

    with (args.output_dir / "audit-summary.md").open(
        "w",
        encoding="utf-8",
    ) as summary:
        print("# Stage 9F-4C optimized machine-code audit", file=summary)
        print(file=summary)

        for target, lines in functions.items():
            classification = classify(lines)
            excerpt = args.output_dir / f"{target}.asm.txt"
            excerpt.write_text("\n".join(lines) + "\n", encoding="utf-8")

            print(f"## `{target}`", file=summary)
            print(f"- recovered lines: {len(lines)}", file=summary)

            for category, values in classification.items():
                print(f"- {category}: {len(values)}", file=summary)

            if not lines:
                print("- status: wrapper symbol not recovered", file=summary)
            else:
                print("- status: recovered", file=summary)

            print(file=summary)

    with (args.output_dir / "flagged-instructions.md").open(
        "w",
        encoding="utf-8",
    ) as stream:
        print("# Flagged instruction excerpts", file=stream)
        print(file=stream)

        for target, lines in functions.items():
            classification = classify(lines)
            print(f"## `{target}`", file=stream)

            for category, values in classification.items():
                print(f"### {category}", file=stream)
                if values:
                    for value in values:
                        print(f"- `{value}`", file=stream)
                else:
                    print("- none", file=stream)

            print(file=stream)

    print("Optimized wrapper audit complete.")


if __name__ == "__main__":
    main()
