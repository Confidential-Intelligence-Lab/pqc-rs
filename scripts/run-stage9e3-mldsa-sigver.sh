#!/usr/bin/env bash
set -euo pipefail

VECTOR_DIR="${1:-vectors/nist-acvp/mldsa-sigver}"
OUT_DIR="target/stage9e3"
mkdir -p "${OUT_DIR}"

./scripts/fetch-stage9e3-mldsa-sigver-vectors.sh "${VECTOR_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-acvp-sigver-pure \
  --release \
  -- \
  "${VECTOR_DIR}/prompt.json" \
  "${OUT_DIR}/response.json" \
  "${VECTOR_DIR}/expectedResults.json" \
  | tee "${OUT_DIR}/mldsa-acvp-sigver-pure.log"

cp "${VECTOR_DIR}/SOURCE.txt" "${OUT_DIR}/SOURCE.txt"

echo "Stage 9E-3 ACVP ML-DSA external-pure sigVer comparison passed."
