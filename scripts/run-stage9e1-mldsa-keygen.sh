#!/usr/bin/env bash
set -euo pipefail
VECTOR_DIR="${1:-vectors/nist-acvp/mldsa-keygen}"
OUT_DIR="target/stage9e1"
mkdir -p "${OUT_DIR}"
./scripts/fetch-stage9e1-mldsa-keygen-vectors.sh "${VECTOR_DIR}"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo run -p pqc-rs-test-harness --bin mldsa-acvp-keygen --release -- \
  "${VECTOR_DIR}/prompt.json" "${OUT_DIR}/response.json" "${VECTOR_DIR}/expectedResults.json" \
  | tee "${OUT_DIR}/mldsa-acvp-keygen.log"
cp "${VECTOR_DIR}/SOURCE.txt" "${OUT_DIR}/SOURCE.txt"
echo "Stage 9E-1 ACVP ML-DSA keyGen comparison passed."
