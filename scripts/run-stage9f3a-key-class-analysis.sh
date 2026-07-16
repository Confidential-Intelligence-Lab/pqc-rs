#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f3a}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-key-class-trace \
  --release \
  -- \
  "${OUT_DIR}/key-class-traces.csv" \
  | tee "${OUT_DIR}/trace-run.txt"

python3 scripts/analyze-stage9f3a-key-classes.py \
  "${OUT_DIR}/key-class-traces.csv" \
  | tee "${OUT_DIR}/key-class-analysis.txt"

echo "Stage 9F-3A fixed/varying-key conditioned analysis complete."
