#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-vectors/nist-acvp}"
OUT_DIR="target/stage9e5"
mkdir -p "${OUT_DIR}"

./scripts/fetch-stage9e5-hash-vectors.sh "${ROOT}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

cargo run   -p pqc-rs-test-harness   --bin mldsa-acvp-hash-siggen   --release   --   "${ROOT}/mldsa-siggen/prompt.json"   "${OUT_DIR}/siggen-response.json"   "${ROOT}/mldsa-siggen/expectedResults.json"   | tee "${OUT_DIR}/siggen.log"

cargo run   -p pqc-rs-test-harness   --bin mldsa-acvp-hash-sigver   --release   --   "${ROOT}/mldsa-sigver/prompt.json"   "${OUT_DIR}/sigver-response.json"   "${ROOT}/mldsa-sigver/expectedResults.json"   | tee "${OUT_DIR}/sigver.log"

echo "Stage 9E-5 HashML-DSA ACVP validation passed."
