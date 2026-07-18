#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
required = {
    "manifest": root / "compliance/implementation-matrix.toml",
    "document": root / "docs/IMPLEMENTATION_MATRIX.md",
    "workflow": root / ".github/workflows/implementation-matrix.yml",
    "xtask": root / "xtask/src/main.rs",
    "readme": root / "README.md",
}
missing = [name for name, path in required.items() if not path.is_file()]
if missing:
    raise SystemExit(f"missing B1.2.1 artifacts: {', '.join(missing)}")

xtask = required["xtask"].read_text()
readme = required["readme"].read_text()
workflow = required["workflow"].read_text()
checks = [
    ("implementation-matrix command", 'Some("implementation-matrix")' in xtask),
    ("check mode", '"--check" => check = true' in xtask),
    ("README link", "docs/IMPLEMENTATION_MATRIX.md" in readme),
    ("CI stale check", "implementation-matrix --check" in workflow),
]
failed = [name for name, ok in checks if not ok]
if failed:
    raise SystemExit(f"B1.2.1 validation failed: {', '.join(failed)}")
print("B1.2.1 static validation: pass")
