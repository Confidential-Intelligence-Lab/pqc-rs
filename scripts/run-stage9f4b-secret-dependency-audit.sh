#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4b}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

./scripts/extract-stage9f4b-assembly.sh "${OUT_DIR}"

python3 scripts/analyze-stage9f4b-secret-dependencies.py \
  "${OUT_DIR}/release" \
  "${OUT_DIR}/debug" \
  "${OUT_DIR}"

python3 scripts/summarize-stage9f4b-audit.py \
  "${OUT_DIR}/release-targeted-audit.md" \
  "${OUT_DIR}/triage-summary.md"

echo "Stage 9F-4B assembly inspection and secret-dependency audit complete."
