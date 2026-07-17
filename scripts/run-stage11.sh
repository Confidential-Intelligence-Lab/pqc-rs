#!/usr/bin/env bash
set -euo pipefail

python3 scripts/validate-stage11.py
python3 scripts/stage11_sidechannel.py --list
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

echo "Stage 11 framework validation and workspace regression passed."
echo "Enable and wire experiment manifests under sidechannel/experiments/ before collecting evidence."
