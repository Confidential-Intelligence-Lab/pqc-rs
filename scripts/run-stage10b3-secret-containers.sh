#!/usr/bin/env bash
set -euo pipefail

python3 scripts/patch-stage10b3-enable-containers.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-core --all-features
cargo test --workspace --all-features

cargo build \
  -p pqc-rs-test-harness \
  --bin ct-stage10b3-audit \
  --release

echo "Stage 10B-3 typed secret assignment validation passed."
