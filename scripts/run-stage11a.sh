#!/usr/bin/env bash
set -euo pipefail
python3 scripts/validate-stage11.py
python3 scripts/validate-stage11a.py
python3 scripts/stage11_sidechannel.py --list
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/collect-stage11a.sh
echo "Stage 11A wiring and workspace regression completed."
