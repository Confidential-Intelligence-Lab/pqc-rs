#!/usr/bin/env bash
set -euo pipefail

python3 scripts/patch-stage10b4-enable-zeroize.py
python3 scripts/patch-stage10b4-secret-drop.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-core --all-features
cargo test --workspace --all-features

./scripts/audit-stage10b4-zeroization.sh

echo "Stage 10B-4 zeroization and secret lifecycle validation passed."
