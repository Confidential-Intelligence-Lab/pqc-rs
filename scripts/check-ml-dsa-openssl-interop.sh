#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

python3 -m py_compile \
  scripts/openssl_provider_interop.py \
  scripts/interop/providers/openssl_provider.py \
  scripts/ml_dsa_openssl_interop.py

python3 - <<'PY'
from pathlib import Path

xtask = Path("xtask/src/main.rs").read_text(encoding="utf-8")
required = [
    'Some("interop-openssl") => interop_openssl(args.collect())',
    "fn interop_openssl(",
    "scripts/openssl_provider_interop.py",
]
missing = [item for item in required if item not in xtask]
if missing:
    raise SystemExit(f"missing xtask OpenSSL contract: {missing}")
PY

python3 scripts/ml_dsa_openssl_interop.py \
  --root "$root" \
  --output target/stage15a7-openssl-mldsa \
  --strict

python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(
    Path("target/stage15a7-openssl-mldsa/report.json").read_text(encoding="utf-8")
)
summary = report["summary"]
if report["decision"] != "pass":
    raise SystemExit("OpenSSL ML-DSA report did not pass")
if summary != {"expected": 24, "executed": 24, "passed": 24, "failed": 0}:
    raise SystemExit(f"unexpected OpenSSL ML-DSA summary: {summary}")

parameter_sets = {result["parameter_set"] for result in report["results"]}
if parameter_sets != {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}:
    raise SystemExit(f"incomplete parameter-set coverage: {parameter_sets}")

directions = {
    (result["producer"], result["consumer"]) for result in report["results"]
}
if directions != {("rust", "openssl"), ("openssl", "rust")}:
    raise SystemExit(f"incomplete direction coverage: {directions}")

mutations = {result["mutation"] for result in report["results"]}
if mutations != {"none", "message", "context", "signature"}:
    raise SystemExit(f"incomplete negative coverage: {mutations}")
PY

echo "Stage 15A-7 OpenSSL ML-DSA interoperability contract: pass"
