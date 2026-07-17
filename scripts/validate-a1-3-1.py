#!/usr/bin/env python3
from __future__ import annotations
import json
import pathlib
import py_compile
import subprocess
import sys

root = pathlib.Path(__file__).resolve().parents[1]
required = [
    root / "scripts/standards_engine.py",
    root / "compliance/schemas/standards-report-v2.schema.json",
    root / "README-a1-3-1.md",
]
missing = [str(path.relative_to(root)) for path in required if not path.exists()]
if missing:
    print("decision=fail")
    print("missing=" + ",".join(missing))
    raise SystemExit(1)

py_compile.compile(str(root / "scripts/standards_engine.py"), doraise=True)
json.loads((root / "compliance/schemas/standards-report-v2.schema.json").read_text())
completed = subprocess.run(
    [sys.executable, "scripts/standards_engine.py", "validate", "--strict", "--structural-only"],
    cwd=root,
    check=False,
)
print("validator=" + ("pass" if completed.returncode == 0 else "fail"))
raise SystemExit(completed.returncode)
