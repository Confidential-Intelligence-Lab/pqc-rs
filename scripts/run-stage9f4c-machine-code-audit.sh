#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4c}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

./scripts/build-stage9f4c-audit-binary.sh "${OUT_DIR}"

python3 scripts/analyze-stage9f4c-machine-code.py \
  "${OUT_DIR}/audit-binary.objdump.txt" \
  "${OUT_DIR}"

echo "Stage 9F-4C optimized machine-code recovery complete."
