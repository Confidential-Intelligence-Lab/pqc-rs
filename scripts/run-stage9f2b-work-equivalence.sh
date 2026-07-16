#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f2b}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-challenge-work-report \
  --release \
  -- \
  "${OUT_DIR}/challenge-work.csv" \
  | tee "${OUT_DIR}/challenge-work-report.txt"

echo "Stage 9F-2B algorithmic work-equivalence validation passed."
