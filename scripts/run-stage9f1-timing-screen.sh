#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f1}"
SAMPLES="${STAGE9F_SAMPLES:-20000}"
WARMUP="${STAGE9F_WARMUP:-200}"

mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

./scripts/audit-stage9f1-source.sh "${OUT_DIR}"

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-timing-screen \
  --release \
  -- \
  keygen "${OUT_DIR}/keygen.csv" "${SAMPLES}" "${WARMUP}"

python3 scripts/analyze-stage9f1-timing.py \
  "${OUT_DIR}/keygen.csv" \
  | tee "${OUT_DIR}/keygen-analysis.txt"

cargo run \
  -p pqc-rs-test-harness \
  --bin mldsa-timing-screen \
  --release \
  -- \
  sign "${OUT_DIR}/sign.csv" "${SAMPLES}" "${WARMUP}"

python3 scripts/analyze-stage9f1-timing.py \
  "${OUT_DIR}/sign.csv" \
  | tee "${OUT_DIR}/sign-analysis.txt"

echo "Stage 9F-1 timing screening complete."
echo "Review the classifications; this stage does not impose a pass/fail gate."
