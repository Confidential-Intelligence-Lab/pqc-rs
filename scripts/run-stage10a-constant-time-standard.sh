#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

python3 scripts/validate-stage10a-constant-time-standard.py

echo "Stage 10A complete."
