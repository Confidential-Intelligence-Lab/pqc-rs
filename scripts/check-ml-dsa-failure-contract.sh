#!/usr/bin/env bash
set -euo pipefail

REPO=${1:-.}
cd "${REPO}"

python3 - <<'PY'
from pathlib import Path
import re
import sys

root = Path("crates/pqc-ml-dsa/src")
forbidden = re.compile(
    r"(?:\.\s*(?:unwrap|expect)\s*\(|\b(?:panic|todo|unimplemented|unreachable)!\s*\()"
)
violations = []

for path in sorted(root.glob("*.rs")):
    text = path.read_text(encoding="utf-8")
    text = text.split("#[cfg(test)]", 1)[0]
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        if forbidden.search(line):
            violations.append(f"{path}:{number}:{line.strip()}")

if violations:
    print("caller-triggerable panic constructs found in ML-DSA production source:")
    print("\n".join(violations))
    sys.exit(1)
PY

cargo test --locked -p pqc-rs-ml-dsa --test failure_contract
cargo test --locked -p pqc-rs-ml-dsa --lib sample::tests::vector_nonce_overflow_is_reported \
  --features internal-api

echo "ML-DSA failure and misuse contract: pass"
