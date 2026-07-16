#!/usr/bin/env python3
"""Inventory branches, divisions, and memory-indexing patterns in Rust assembly."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from pathlib import Path

FUNCTION_PATTERNS = (
    "multiply_challenge",
    "sign_internal",
    "sign_prepared",
    "verify_internal",
    "verify_with_mu",
    "sample_eta_poly",
    "sample_in_ball",
    "ntt",
    "inv_ntt",
    "high_bits",
    "low_bits",
    "encode_",
    "decode_",
)

BRANCH_RE = re.compile(
    r"^\s*(b\.[a-z]+|b[a-z]+|cbz|cbnz|tbz|tbnz|j[a-z]+)\b",
    re.IGNORECASE,
)
DIV_RE = re.compile(
    r"^\s*(sdiv|udiv|idiv|div|fdiv)\b",
    re.IGNORECASE,
)
INDIRECT_RE = re.compile(
    r"^\s*(br|blr|jmp\s+\*|call\s+\*)\b",
    re.IGNORECASE,
)
LOAD_STORE_RE = re.compile(
    r"^\s*(ldr|ldp|ldur|str|stp|stur|mov|lea)\b",
    re.IGNORECASE,
)


def collect_assembly(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.s"))


def classify_line(line: str, counters: Counter[str]) -> None:
    stripped = line.strip()

    if BRANCH_RE.search(stripped):
        counters["conditional_branches"] += 1
    if DIV_RE.search(stripped):
        counters["division_instructions"] += 1
    if INDIRECT_RE.search(stripped):
        counters["indirect_control_flow"] += 1
    if LOAD_STORE_RE.search(stripped):
        counters["load_store_like"] += 1


def function_mentions(text: str) -> dict[str, int]:
    lowered = text.lower()
    return {
        pattern: lowered.count(pattern.lower())
        for pattern in FUNCTION_PATTERNS
    }


def analyze(directory: Path) -> tuple[Counter[str], dict[str, int], int]:
    counters: Counter[str] = Counter()
    mentions = {pattern: 0 for pattern in FUNCTION_PATTERNS}
    total_lines = 0

    for path in collect_assembly(directory):
        text = path.read_text(encoding="utf-8", errors="replace")
        total_lines += len(text.splitlines())

        for line in text.splitlines():
            classify_line(line, counters)

        for pattern, count in function_mentions(text).items():
            mentions[pattern] += count

    return counters, mentions, total_lines


def write_report(
    output: Path,
    label: str,
    directory: Path,
    counters: Counter[str],
    mentions: dict[str, int],
    total_lines: int,
) -> None:
    files = collect_assembly(directory)

    with output.open("w", encoding="utf-8") as stream:
        print(f"# {label} generated-code audit", file=stream)
        print(file=stream)
        print(f"assembly files: {len(files)}", file=stream)
        print(f"assembly lines: {total_lines}", file=stream)
        print(file=stream)
        print("## Instruction inventory", file=stream)
        for key in (
            "conditional_branches",
            "division_instructions",
            "indirect_control_flow",
            "load_store_like",
        ):
            print(f"{key}: {counters[key]}", file=stream)

        print(file=stream)
        print("## Symbol/name mentions", file=stream)
        for pattern, count in mentions.items():
            print(f"{pattern}: {count}", file=stream)

        print(file=stream)
        print("## Files", file=stream)
        for path in files:
            print(path.name, file=stream)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("debug_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    release = analyze(args.release_dir)
    debug = analyze(args.debug_dir)

    write_report(
        args.output_dir / "release-audit.txt",
        "release",
        args.release_dir,
        *release,
    )
    write_report(
        args.output_dir / "debug-audit.txt",
        "debug",
        args.debug_dir,
        *debug,
    )

    release_counts, _, _ = release
    debug_counts, _, _ = debug

    with (args.output_dir / "debug-release-diff.txt").open(
        "w",
        encoding="utf-8",
    ) as stream:
        print("# Debug versus release generated-code inventory", file=stream)
        for key in (
            "conditional_branches",
            "division_instructions",
            "indirect_control_flow",
            "load_store_like",
        ):
            print(
                f"{key}: debug={debug_counts[key]} "
                f"release={release_counts[key]} "
                f"delta={release_counts[key] - debug_counts[key]}",
                file=stream,
            )

    print("Generated release/debug audit reports.")


if __name__ == "__main__":
    main()
