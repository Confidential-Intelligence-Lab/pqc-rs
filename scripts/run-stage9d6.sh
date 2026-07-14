#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="target/stage9d6"
mkdir -p "${OUT_DIR}"

echo "== Formatting =="
cargo fmt --all -- --check

echo "== Clippy =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== ML-DSA tests =="
cargo test -p pqc-rs-ml-dsa --all-features

echo "== Workspace tests =="
cargo test --workspace --all-features

echo "== Documentation =="
RUSTDOCFLAGS="-D warnings" cargo doc -p pqc-rs-ml-dsa --all-features --no-deps

echo "== Deterministic validation matrix =="
cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-stage9d-validation \
  --release \
  | tee "${OUT_DIR}/mldsa-stage9d-validation.log"

echo "== Dependency policy =="
cargo deny check

echo "Stage 9D-6 local validation passed."
echo "External ACVP/reference-vector validation remains required for a conformance claim."
