#!/usr/bin/env python3
"""Targeted generated-code audit for ML-DSA secret-bearing primitives."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, field
from pathlib import Path


TARGETS = (
    "multiply_challenge",
    "sign_prepared",
    "verify_with_mu",
    "sample_eta_poly",
    "sample_in_ball",
    "high_bits",
    "low_bits",
    "power2round",
    "ntt",
    "inv_ntt",
    "encode_t0",
    "decode_t0",
    "encode_z",
    "decode_z",
)

CONDITIONAL_BRANCH = re.compile(
    r"^\s*(?:b\.[a-z]+|b(?:eq|ne|lt|le|gt|ge|hi|hs|lo|ls|mi|pl|vs|vc)|"
    r"cbz|cbnz|tbz|tbnz|j[a-z]+)\b",
    re.IGNORECASE,
)
UNCONDITIONAL_BRANCH = re.compile(
    r"^\s*(?:b|br|jmp)\b",
    re.IGNORECASE,
)
CONDITIONAL_MOVE = re.compile(
    r"^\s*(?:csel|csinc|csinv|csneg|cmov[a-z]*)\b",
    re.IGNORECASE,
)
DIVISION = re.compile(
    r"^\s*(?:sdiv|udiv|idiv|div)\b",
    re.IGNORECASE,
)
TABLE_OR_INDEXED_MEMORY = re.compile(
    r"(?:\[[^\]]*,\s*[wx][0-9]+\s*(?:,\s*(?:lsl|uxtw|sxtw))?|"
    r"\([^)]*,[^)]*,[1248]\))",
    re.IGNORECASE,
)
LOAD_STORE = re.compile(
    r"^\s*(?:ldr|ldp|ldur|str|stp|stur|mov|lea)\b",
    re.IGNORECASE,
)
MULTIPLY = re.compile(
    r"^\s*(?:mul|madd|msub|smull|umull|imul)\b",
    re.IGNORECASE,
)


@dataclass
class FunctionAudit:
    name: str
    lines: list[str] = field(default_factory=list)
    conditional_branches: list[str] = field(default_factory=list)
    unconditional_branches: list[str] = field(default_factory=list)
    conditional_moves: list[str] = field(default_factory=list)
    divisions: list[str] = field(default_factory=list)
    indexed_memory: list[str] = field(default_factory=list)
    load_store: list[str] = field(default_factory=list)
    multiplies: list[str] = field(default_factory=list)


def symbol_name(line: str) -> str | None:
    stripped = line.strip()

    if not stripped.endswith(":"):
        return None

    label = stripped[:-1]
    if label.startswith(".L"):
        return None
    if label.startswith("LBB"):
        return None
    return label


def demangled_target(symbol: str) -> str | None:
    lowered = symbol.lower()
    for target in TARGETS:
        if target.lower() in lowered:
            return target
    return None


def analyze_file(path: Path) -> dict[str, list[FunctionAudit]]:
    audits: dict[str, list[FunctionAudit]] = {target: [] for target in TARGETS}
    current: FunctionAudit | None = None

    for raw_line in path.read_text(
        encoding="utf-8",
        errors="replace",
    ).splitlines():
        symbol = symbol_name(raw_line)

        if symbol is not None:
            target = demangled_target(symbol)
            current = FunctionAudit(symbol) if target else None
            if current is not None:
                audits[target].append(current)

        if current is None:
            continue

        current.lines.append(raw_line)

        if CONDITIONAL_BRANCH.search(raw_line):
            current.conditional_branches.append(raw_line.strip())
        elif UNCONDITIONAL_BRANCH.search(raw_line):
            current.unconditional_branches.append(raw_line.strip())

        if CONDITIONAL_MOVE.search(raw_line):
            current.conditional_moves.append(raw_line.strip())
        if DIVISION.search(raw_line):
            current.divisions.append(raw_line.strip())
        if TABLE_OR_INDEXED_MEMORY.search(raw_line):
            current.indexed_memory.append(raw_line.strip())
        if LOAD_STORE.search(raw_line):
            current.load_store.append(raw_line.strip())
        if MULTIPLY.search(raw_line):
            current.multiplies.append(raw_line.strip())

    return audits


def merge(
    destination: dict[str, list[FunctionAudit]],
    source: dict[str, list[FunctionAudit]],
) -> None:
    for target, audits in source.items():
        destination[target].extend(audits)


def analyze_directory(directory: Path) -> dict[str, list[FunctionAudit]]:
    merged = {target: [] for target in TARGETS}
    for path in sorted(directory.glob("*.s")):
        merge(merged, analyze_file(path))
    return merged


def summarize(
    output: Path,
    label: str,
    audits: dict[str, list[FunctionAudit]],
) -> None:
    with output.open("w", encoding="utf-8") as stream:
        print(f"# {label} targeted assembly audit", file=stream)
        print(file=stream)

        for target in TARGETS:
            entries = audits[target]
            print(f"## {target}", file=stream)
            print(f"matched symbols: {len(entries)}", file=stream)

            if not entries:
                print("status: symbol not located", file=stream)
                print(file=stream)
                continue

            total_lines = sum(len(entry.lines) for entry in entries)
            branches = sum(
                len(entry.conditional_branches) for entry in entries
            )
            moves = sum(len(entry.conditional_moves) for entry in entries)
            divisions = sum(len(entry.divisions) for entry in entries)
            indexed = sum(len(entry.indexed_memory) for entry in entries)
            loads = sum(len(entry.load_store) for entry in entries)
            multiplies = sum(len(entry.multiplies) for entry in entries)

            print(f"assembly lines: {total_lines}", file=stream)
            print(f"conditional branches: {branches}", file=stream)
            print(f"conditional moves/selects: {moves}", file=stream)
            print(f"division instructions: {divisions}", file=stream)
            print(f"indexed-memory candidates: {indexed}", file=stream)
            print(f"load/store-like instructions: {loads}", file=stream)
            print(f"multiply-like instructions: {multiplies}", file=stream)
            print(file=stream)

            for entry in entries:
                print(f"### symbol `{entry.name}`", file=stream)

                for heading, values in (
                    ("conditional branches", entry.conditional_branches),
                    ("conditional moves/selects", entry.conditional_moves),
                    ("division instructions", entry.divisions),
                    ("indexed-memory candidates", entry.indexed_memory),
                ):
                    print(f"#### {heading}", file=stream)
                    if values:
                        for value in values[:100]:
                            print(f"- `{value}`", file=stream)
                    else:
                        print("- none detected", file=stream)

                print(file=stream)


def write_excerpts(
    output_dir: Path,
    audits: dict[str, list[FunctionAudit]],
) -> None:
    excerpt_dir = output_dir / "excerpts"
    excerpt_dir.mkdir(parents=True, exist_ok=True)

    for target, entries in audits.items():
        with (excerpt_dir / f"{target}.s.txt").open(
            "w",
            encoding="utf-8",
        ) as stream:
            for entry in entries:
                print(f"# {entry.name}", file=stream)
                print("\n".join(entry.lines), file=stream)
                print(file=stream)


def write_review_matrix(output: Path) -> None:
    rows = {
        "multiply_challenge": (
            "challenge support and polynomial coefficients",
            "support-dependent branch is expected; coefficient-dependent "
            "branches or indexed loads require investigation",
        ),
        "sign_prepared": (
            "private key, message representative, randomness",
            "rejection branches are expected; inspect residual secret-dependent "
            "branches inside each attempt",
        ),
        "verify_with_mu": (
            "public key, signature, message representative",
            "inputs are public; variable-time behavior is not a secret leak",
        ),
        "sample_eta_poly": (
            "private-key seed expansion",
            "data-dependent loops, branches, or table indices require review",
        ),
        "sample_in_ball": (
            "challenge seed",
            "challenge is transcript-derived; inspect variable loops and indexed "
            "swaps",
        ),
        "high_bits": (
            "secret-bearing coefficients during signing",
            "division or conditional correction requires assembly review",
        ),
        "low_bits": (
            "secret-bearing coefficients during signing",
            "division or conditional correction requires assembly review",
        ),
        "ntt": (
            "secret and ephemeral polynomial coefficients",
            "fixed loop bounds expected; indexed twiddle access should depend "
            "only on public loop indices",
        ),
    }

    with output.open("w", encoding="utf-8") as stream:
        print("# Secret-dependency review matrix", file=stream)
        print(file=stream)
        print("| Primitive | Sensitive inputs | Review criterion |", file=stream)
        print("|---|---|---|", file=stream)

        for primitive, (inputs, criterion) in rows.items():
            print(
                f"| `{primitive}` | {inputs} | {criterion} |",
                file=stream,
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("debug_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    release = analyze_directory(args.release_dir)
    debug = analyze_directory(args.debug_dir)

    summarize(
        args.output_dir / "release-targeted-audit.md",
        "Release",
        release,
    )
    summarize(
        args.output_dir / "debug-targeted-audit.md",
        "Debug",
        debug,
    )
    write_excerpts(args.output_dir / "release", release)
    write_excerpts(args.output_dir / "debug", debug)
    write_review_matrix(args.output_dir / "secret-dependency-matrix.md")

    print("Targeted assembly and secret-dependency audit complete.")


if __name__ == "__main__":
    main()
