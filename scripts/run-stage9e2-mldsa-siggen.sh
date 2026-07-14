#!/usr/bin/env bash
set -euo pipefail

VECTOR_DIR="${1:-vectors/nist-acvp/mldsa-siggen}"
OUT_DIR="target/stage9e2"
mkdir -p "${OUT_DIR}"

./scripts/fetch-stage9e2-mldsa-siggen-vectors.sh "${VECTOR_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-acvp-siggen-pure \
  --release \
  -- \
  "${VECTOR_DIR}/prompt.json" \
  "${OUT_DIR}/response.json" \
  "${VECTOR_DIR}/expectedResults.json" \
  | tee "${OUT_DIR}/mldsa-acvp-siggen-pure.log"

cp "${VECTOR_DIR}/SOURCE.txt" "${OUT_DIR}/SOURCE.txt"

echo "Stage 9E-2A ACVP ML-DSA external-pure sigGen comparison passed."
