#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, re
from pathlib import Path

HEADER_RE = re.compile(r"^## `([^`]+)`$")
CATEGORY_RE = re.compile(r"^### (.+)$")
INSTRUCTION_RE = re.compile(r"^- `(.+)`$")

DEFAULTS = {
    ("audit_multiply_challenge", "conditional_branches"):
        ("transcript-derived", "expected",
         "Sparse challenge support branch; challenge is transcript-derived."),
    ("audit_rounding", "conditional_branches"):
        ("public-loop-index", "expected",
         "Fixed wrapper-loop termination."),
    ("audit_rounding", "conditional_selects"):
        ("secret-coefficient", "constant-time-select",
         "ARM64 csel implements arithmetic correction without branching."),
}

FIELDS = [
    "target","category","instruction","source_file","source_line",
    "dependency","classification","rationale","reviewer","status",
]

def parse_flagged(path: Path):
    rows, target, category = [], "", ""
    for line in path.read_text(encoding="utf-8").splitlines():
        match = HEADER_RE.match(line)
        if match:
            target, category = match.group(1), ""
            continue
        match = CATEGORY_RE.match(line)
        if match:
            category = match.group(1)
            continue
        match = INSTRUCTION_RE.match(line)
        if match and match.group(1) != "none":
            dependency, classification, rationale = DEFAULTS.get(
                (target, category),
                ("unclassified", "review", "Manual classification required."),
            )
            rows.append({
                "target": target,
                "category": category,
                "instruction": match.group(1),
                "source_file": "",
                "source_line": "",
                "dependency": dependency,
                "classification": classification,
                "rationale": rationale,
                "reviewer": "",
                "status": "provisional" if classification != "review" else "open",
            })
    return rows

def write_csv(path: Path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

def write_md(path: Path, rows):
    with path.open("w", encoding="utf-8") as stream:
        print("# Stage 9F-4D instruction classification", file=stream)
        print(file=stream)
        print("| Target | Category | Instruction | Dependency | Classification | Status | Rationale |", file=stream)
        print("|---|---|---|---|---|---|---|", file=stream)
        for row in rows:
            rationale = row["rationale"].replace("|", "\\|")
            print(f"| `{row['target']}` | {row['category']} | `{row['instruction']}` | "
                  f"{row['dependency']} | {row['classification']} | {row['status']} | {rationale} |",
                  file=stream)

def validate(path: Path):
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    unresolved = []
    secret_branches = []
    for index, row in enumerate(rows, start=2):
        if row["status"] not in {"closed", "accepted"}:
            unresolved.append((index, row))
        if (row["category"] == "conditional_branches"
            and row["dependency"] in {"secret-key","secret-coefficient","secret-intermediate"}
            and row["classification"] not in {"declassified","mitigated","expected-rejection"}):
            secret_branches.append((index, row))
    print(f"classified instructions: {len(rows)}")
    print(f"unresolved instructions: {len(unresolved)}")
    print(f"unresolved secret-dependent branches: {len(secret_branches)}")
    for line, row in unresolved:
        print(f"open CSV line {line}: {row['target']} {row['instruction']}")
    for line, row in secret_branches:
        print(f"secret branch CSV line {line}: {row['target']} {row['instruction']}")
    return 2 if secret_branches else (1 if unresolved else 0)

def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    init = subs.add_parser("init")
    init.add_argument("flagged", type=Path)
    init.add_argument("csv_output", type=Path)
    init.add_argument("markdown_output", type=Path)
    check = subs.add_parser("validate")
    check.add_argument("csv", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        rows = parse_flagged(args.flagged)
        write_csv(args.csv_output, rows)
        write_md(args.markdown_output, rows)
        print(f"initialized {len(rows)} instruction records")
    else:
        raise SystemExit(validate(args.csv))

if __name__ == "__main__":
    main()
