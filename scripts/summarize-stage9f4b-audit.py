#!/usr/bin/env python3
"""Create a concise triage summary from Stage 9F-4B reports."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


TARGET_RE = re.compile(r"^## (.+)$")
COUNT_RE = re.compile(r"^(conditional branches|conditional moves/selects|division instructions|indexed-memory candidates): (\d+)$")


def parse(path: Path) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    current: str | None = None

    for line in path.read_text(encoding="utf-8").splitlines():
        target_match = TARGET_RE.match(line)

        if target_match:
            current = target_match.group(1)
            result[current] = {}
            continue

        count_match = COUNT_RE.match(line)
        if current is not None and count_match:
            result[current][count_match.group(1)] = int(count_match.group(2))

    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_report", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    data = parse(args.release_report)

    with args.output.open("w", encoding="utf-8") as stream:
        print("# Stage 9F-4B triage summary", file=stream)
        print(file=stream)

        for primitive, counts in data.items():
            divisions = counts.get("division instructions", 0)
            branches = counts.get("conditional branches", 0)
            indexed = counts.get("indexed-memory candidates", 0)
            moves = counts.get("conditional moves/selects", 0)

            flags = []
            if divisions:
                flags.append("division")
            if indexed:
                flags.append("indexed-memory")
            if branches:
                flags.append("conditional-branch")
            if moves:
                flags.append("conditional-select")

            status = ", ".join(flags) if flags else "no flagged instruction classes"

            print(f"## {primitive}", file=stream)
            print(f"- status: {status}", file=stream)
            print(f"- conditional branches: {branches}", file=stream)
            print(f"- conditional moves/selects: {moves}", file=stream)
            print(f"- division instructions: {divisions}", file=stream)
            print(f"- indexed-memory candidates: {indexed}", file=stream)
            print(file=stream)

        print(
            "Manual review remains required: assembly classification alone "
            "cannot determine whether an instruction depends on secret data.",
            file=stream,
        )

    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
