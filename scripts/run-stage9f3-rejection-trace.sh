#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f3}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-signing-rejection-trace \
  --release \
  -- \
  "${OUT_DIR}/signing-rejections.csv" \
  | tee "${OUT_DIR}/trace-run.txt"

python3 scripts/analyze-stage9f3-rejections.py \
  "${OUT_DIR}/signing-rejections.csv" \
  | tee "${OUT_DIR}/signing-rejections-analysis.txt"

echo "Stage 9F-3 signing rejection-loop characterization complete."
