#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-vectors/nist-acvp}"
OUT="target/stage9e4"
mkdir -p "${OUT}"
./scripts/fetch-stage9e4-internal-vectors.sh "${ROOT}"
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features
cargo run -p pqc-rs-test-harness --bin mldsa-acvp-siggen-internal --release -- \
 "${ROOT}/mldsa-siggen/prompt.json" "${OUT}/siggen-response.json" "${ROOT}/mldsa-siggen/expectedResults.json" | tee "${OUT}/siggen.log"
cargo run -p pqc-rs-test-harness --bin mldsa-acvp-sigver-internal --release -- \
 "${ROOT}/mldsa-sigver/prompt.json" "${OUT}/sigver-response.json" "${ROOT}/mldsa-sigver/expectedResults.json" | tee "${OUT}/sigver.log"
echo "Stage 9E-4 ACVP ML-DSA internal-interface validation passed."
