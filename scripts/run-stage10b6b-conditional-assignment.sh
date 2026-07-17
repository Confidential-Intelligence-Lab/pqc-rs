#!/usr/bin/env bash
set -euo pipefail

python3 scripts/inventory-stage10b6b-conditional-assignment.py
python3 scripts/patch-stage10b6b-conditional-assignment.py
python3 scripts/report-stage10b6b-open-sites.py

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-kem --all-features
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

python3 scripts/validate-stage10b6b.py

echo "Stage 10B-6B conditional assignment and selection migration passed."
