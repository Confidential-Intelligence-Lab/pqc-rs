#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

./scripts/extract-stage9f4-assembly.sh "${OUT_DIR}"

python3 scripts/analyze-stage9f4-assembly.py \
  "${OUT_DIR}/asm-release" \
  "${OUT_DIR}/asm-debug" \
  "${OUT_DIR}"

./scripts/extract-stage9f4-symbol-excerpts.sh "${OUT_DIR}"

echo "Stage 9F-4 compiler and generated-code audit complete."
