#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4b}"
mkdir -p "${OUT_DIR}/release" "${OUT_DIR}/debug"

RUSTFLAGS_RELEASE="${RUSTFLAGS_RELEASE:--C target-cpu=native -C debuginfo=1}"
RUSTFLAGS_DEBUG="${RUSTFLAGS_DEBUG:--C debuginfo=2}"

RUSTFLAGS="${RUSTFLAGS_RELEASE}" cargo rustc \
  -p pqc-rs-ml-dsa \
  --lib \
  --release \
  -- \
  --emit=asm

RUSTFLAGS="${RUSTFLAGS_DEBUG}" cargo rustc \
  -p pqc-rs-ml-dsa \
  --lib \
  -- \
  --emit=asm

find target/release/deps -maxdepth 1 -name 'pqc_rs_ml_dsa-*.s' \
  -exec cp {} "${OUT_DIR}/release/" \;

find target/debug/deps -maxdepth 1 -name 'pqc_rs_ml_dsa-*.s' \
  -exec cp {} "${OUT_DIR}/debug/" \;

rustc --version --verbose > "${OUT_DIR}/rustc-version.txt"
cargo --version > "${OUT_DIR}/cargo-version.txt"
uname -a > "${OUT_DIR}/system.txt"

echo "Assembly extracted under ${OUT_DIR}"
