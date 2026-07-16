#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${1:-target/stage10b2}"
mkdir -p "${OUT_DIR}"
python3 scripts/patch-stage10b2-enable-compare.py
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-core --all-features
cargo test --workspace --all-features
cargo build -p pqc-rs-test-harness --bin ct-stage10b2-audit --release
cargo run -p pqc-rs-test-harness --bin ct-stage10b2-timing --release -- "${OUT_DIR}/mismatch-position-timing.csv"
python3 scripts/analyze-stage10b2-timing.py "${OUT_DIR}/mismatch-position-timing.csv" | tee "${OUT_DIR}/mismatch-position-analysis.txt"
echo "Stage 10B-2 constant-time byte comparison validation passed."
