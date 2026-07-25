#!/usr/bin/env bash
set -eu
set -o pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [repository]" >&2
  exit 64
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=${1:-$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)}

for tool in cargo python3 rg; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "required tool is missing: ${tool}" >&2
    exit 1
  }
done

metadata=$(mktemp "${TMPDIR:-/tmp}/pqc-mldsa-metadata.XXXXXX")
trap 'rm -f "${metadata}"' EXIT

cargo metadata \
  --manifest-path "${REPO}/Cargo.toml" \
  --locked \
  --no-deps \
  --format-version 1 >"${metadata}"

python3 - "${metadata}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    metadata = json.load(stream)

packages = [
    package
    for package in metadata["packages"]
    if package["name"] == "pqc-rs-ml-dsa"
]
if len(packages) != 1:
    raise SystemExit("expected exactly one pqc-rs-ml-dsa package")

expected = {
    "acvp": ["pqc-core/acvp"],
    "bench": ["pqc-core/bench"],
    "default": [],
}
actual = packages[0]["features"]
if actual != expected:
    raise SystemExit(
        "unexpected pqc-rs-ml-dsa feature contract:\n"
        f"expected={expected!r}\nactual={actual!r}"
    )
PY

if rg -n \
  '#!\[cfg_attr\(not\(feature = "std"\), no_std\)\]|#\[cfg\(feature = "std"\)\]' \
  "${REPO}/crates/pqc-ml-dsa/src"; then
  echo "ML-DSA still contains an optional-std or no_std source claim" >&2
  exit 1
fi

if ! rg -q 'requires the Rust standard library' \
  "${REPO}/crates/pqc-ml-dsa/src/lib.rs" \
  "${REPO}/docs/api/ML_DSA_FEATURE_CONTRACT.md"; then
  echo "ML-DSA std-required documentation is missing" >&2
  exit 1
fi

cargo check --manifest-path "${REPO}/Cargo.toml" --locked \
  -p pqc-rs-ml-dsa
cargo check --manifest-path "${REPO}/Cargo.toml" --locked \
  -p pqc-rs-ml-dsa --no-default-features
cargo check --manifest-path "${REPO}/Cargo.toml" --locked \
  -p pqc-rs-ml-dsa --no-default-features --features acvp
cargo check --manifest-path "${REPO}/Cargo.toml" --locked \
  -p pqc-rs-ml-dsa --no-default-features --features bench
cargo check --manifest-path "${REPO}/Cargo.toml" --locked \
  -p pqc-rs-ml-dsa --all-features

echo "ML-DSA std-required feature contract: pass"
