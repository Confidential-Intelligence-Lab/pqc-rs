#!/usr/bin/env python3
"""Validate the A1.1.1 live traceability overlay."""
import json
import pathlib
import shutil
import subprocess
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
required = [
    root / "compliance/matrix.toml",
    root / "compliance/schemas/requirement.schema.json",
    root / "xtask/Cargo.toml",
    root / "xtask/src/main.rs",
    root / "docs/standards/README.md",
    root / "docs/standards/TRACEABILITY.md",
]
missing = [str(path.relative_to(root)) for path in required if not path.exists()]
if missing:
    raise SystemExit("missing: " + ", ".join(missing))

with (root / "compliance/matrix.toml").open("rb") as handle:
    matrix = tomllib.load(handle)
schema = json.loads((root / "compliance/schemas/requirement.schema.json").read_text())
if matrix.get("metadata", {}).get("schema_version") != 2:
    raise SystemExit("expected compliance schema_version = 2")
if not schema.get("$id", "").endswith("compliance-requirement-v2.json"):
    raise SystemExit("expected requirement schema v2")
requirements = matrix.get("requirement", [])
ids = [entry["id"] for entry in requirements]
if not ids or len(ids) != len(set(ids)):
    raise SystemExit("empty or duplicate requirement IDs")
for entry in requirements:
    if entry.get("status") == "verified":
        for field in ("implementation", "tests", "last_verified"):
            if not entry.get(field):
                raise SystemExit(f"{entry['id']}: verified entry missing {field}")
        if not entry.get("evidence") and not entry.get("evidence_paths"):
            raise SystemExit(f"{entry['id']}: verified entry missing evidence")
    if entry.get("status") == "not-applicable" and not entry.get("rationale"):
        raise SystemExit(f"{entry['id']}: not-applicable entry missing rationale")

if shutil.which("cargo"):
    out = root / "target/a1-1-validation"
    subprocess.run(
        [
            "cargo", "run", "--quiet", "--manifest-path", str(root / "xtask/Cargo.toml"),
            "--", "compliance", "--matrix", str(root / "compliance/matrix.toml"),
            "--output", str(out), "--strict",
        ],
        cwd=root,
        check=True,
    )
    for name in ("report.md", "report.json", "report.html", "findings.json"):
        if not (out / name).exists():
            raise SystemExit(f"missing generated {name}")
else:
    print("cargo unavailable; skipped Rust execution check")
print("A1.1.1 live traceability validation passed.")
