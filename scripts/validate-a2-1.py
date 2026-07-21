#!/usr/bin/env python3
"""Structural and executable validation for A2.1."""
from __future__ import annotations
import json
import pathlib
import subprocess
import sys
import tomllib

root = pathlib.Path(__file__).resolve().parents[1]
required = [
    "interop/manifest.toml",
    "interop/schemas/vector-v1.schema.json",
    "interop/schemas/report-v1.schema.json",
    "interop/vectors/framework/echo-sha256.json",
    "scripts/interop_engine.py",
    "scripts/interop/providers/selftest_provider.py",
    "docs/interoperability/README.md",
]
missing = [p for p in required if not (root / p).exists()]
if missing:
    print("missing files:", *missing, sep="\n- ", file=sys.stderr)
    raise SystemExit(1)
with (root / "interop/manifest.toml").open("rb") as handle:
    manifest = tomllib.load(handle)
assert manifest["interop"]["schema_version"] == 1
providers = manifest.get("provider", [])
assert len({p["id"] for p in providers}) == len(providers)
for schema in ("vector-v1.schema.json", "report-v1.schema.json"):
    json.loads((root / "interop/schemas" / schema).read_text())
completed = subprocess.run(
    [
        sys.executable,
        "scripts/interop_engine.py",
        "report",
        "--provider",
        "selftest",
        "--suite",
        "framework-protocol",
        "--strict",
    ],
    cwd=root,
    text=True,
    capture_output=True,
    check=False,
)
print(completed.stdout, end="")
if completed.returncode != 0:
    print(completed.stderr, file=sys.stderr)
    raise SystemExit(completed.returncode)
report = json.loads((root / "target/interop/report.json").read_text())
assert report["decision"] == "pass"
assert report["summary"]["executed"] >= 1
assert report["summary"]["failed"] == 0
print("A2.1 validation: pass")
