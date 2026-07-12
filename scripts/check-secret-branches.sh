#!/usr/bin/env bash
set -euo pipefail

mkdir -p target

python3 - <<'PY'
from pathlib import Path
import re

branch = re.compile(r"\b(if|match|while)\b")
secret = re.compile(
    r"(secret|private|decapsulation|seed|shared_secret|randomness)",
    re.IGNORECASE,
)

findings = []

for path in Path("crates").rglob("*.rs"):
    text = path.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if branch.search(stripped) and secret.search(stripped):
            findings.append(f"{path}:{number}:{line}")

report = Path("target/stage8d-secret-branch-inventory.txt")
report.write_text("\n".join(findings) + ("\n" if findings else ""), encoding="utf-8")

if findings:
    print("\n".join(findings))
    print()
    print("Potential secret-dependent branches require manual classification.")
else:
    print("No obvious secret-dependent branch candidates found.")
PY
