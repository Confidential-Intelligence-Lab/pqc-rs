#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f2}"
mkdir -p "${OUT_DIR}"

cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa --all-features
cargo test --workspace --all-features

for PRIMITIVE in \
  ntt \
  intt \
  sample-eta \
  sample-ball \
  rounding \
  encoding \
  challenge-mul
do
  echo "== ${PRIMITIVE} =="
  cargo run \
    -p pqc-rs-test-harness \
    --bin mldsa-primitive-timing \
    --release \
    -- \
    "${PRIMITIVE}" "${OUT_DIR}/${PRIMITIVE}.csv"

  python3 scripts/analyze-stage9f2.py \
    "${OUT_DIR}/${PRIMITIVE}.csv" \
    | tee "${OUT_DIR}/${PRIMITIVE}-analysis.txt"
done

echo "Stage 9F-2 primitive timing localization complete."
