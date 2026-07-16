#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${1:-target/stage9f2a}"; mkdir -p "${OUT_DIR}"
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features
for E in fixed-challenge varying-challenge matched-distribution; do
 echo "== ${E} =="
 cargo run -p pqc-rs-test-harness --bin mldsa-challenge-timing --release -- "${E}" "${OUT_DIR}/${E}.csv"
 python3 scripts/analyze-stage9f2a.py "${OUT_DIR}/${E}.csv" | tee "${OUT_DIR}/${E}-analysis.txt"
done
echo "Stage 9F-2A challenge decomposition complete."
