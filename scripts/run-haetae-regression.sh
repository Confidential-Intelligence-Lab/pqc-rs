#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="${HAETAE_FIXTURE_BASE:-$HOME/Documents/uci_research/Prelim}"
FIX="$BASE/haetae-signing-retry-parity"

export HAETAE_ETA_PACKING_PARITY_DIR="$BASE/haetae-eta-packing-parity"
export HAETAE_KEYGEN_ARITHMETIC_PARITY_DIR="$BASE/haetae-keygen-arithmetic-parity"
export HAETAE_KEYGEN_COMPLETE_LOOP_PARITY_DIR="$BASE/haetae-keygen-complete-loop-parity"
export HAETAE_KEYGEN_KEYPAIR_PARITY_DIR="$BASE/haetae-keygen-keypair-parity"
export HAETAE_KEYGEN_PREPARATION_PARITY_DIR="$BASE/haetae-keygen-preparation-parity"
export HAETAE_KEYGEN_SEED_PARITY_DIR="$BASE/haetae-keygen-seed-parity"
export HAETAE_MATRIX_PARITY_DIR="$BASE/haetae-matrix-parity"
export HAETAE_POLY_Q_PARITY_DIR="$BASE/haetae-poly-q-parity"
export HAETAE_RANS_PARITY_DIR="$BASE/haetae-rans-parity"
export HAETAE_SIGNING_INITIALIZATION_PARITY_DIR="$BASE/haetae-signing-initialization-parity"
export HAETAE_SIGNING_MATRIX_PARITY_DIR="$BASE/haetae-signing-matrix-parity"
export HAETAE_SIGNING_RETRY_PARITY_DIR="$FIX/rust-fixtures"

export HAETAE_C_VERIFICATION_ROOT="$FIX"
export HAETAE_C_VERIFICATION_MATRIX_PARITY_DIR="$FIX/verification-matrix-parity"
export HAETAE_C_VERIFICATION_MATRIX_PRODUCT_PARITY_DIR="$FIX/verification-matrix-product-parity"
export HAETAE_C_VERIFICATION_NTT_PARITY_DIR="$FIX/verification-ntt-parity"
export HAETAE_C_VERIFY_ARITHMETIC_PARITY_DIR="$FIX/verification-arithmetic-parity"
export HAETAE_C_Z1_COMPOSITION_PARITY_DIR="$FIX/z1-composition-parity"
export HAETAE_DECODER_COEFFICIENT_PARITY_DIR="$FIX/decoder-coefficient-parity"

cd "$REPO"

echo "=== FIXTURE PREFLIGHT ==="

for name in \
  HAETAE_ETA_PACKING_PARITY_DIR \
  HAETAE_KEYGEN_ARITHMETIC_PARITY_DIR \
  HAETAE_KEYGEN_COMPLETE_LOOP_PARITY_DIR \
  HAETAE_KEYGEN_KEYPAIR_PARITY_DIR \
  HAETAE_KEYGEN_PREPARATION_PARITY_DIR \
  HAETAE_KEYGEN_SEED_PARITY_DIR \
  HAETAE_MATRIX_PARITY_DIR \
  HAETAE_POLY_Q_PARITY_DIR \
  HAETAE_RANS_PARITY_DIR \
  HAETAE_SIGNING_INITIALIZATION_PARITY_DIR \
  HAETAE_SIGNING_MATRIX_PARITY_DIR \
  HAETAE_SIGNING_RETRY_PARITY_DIR \
  HAETAE_C_VERIFICATION_ROOT \
  HAETAE_C_VERIFICATION_MATRIX_PARITY_DIR \
  HAETAE_C_VERIFICATION_MATRIX_PRODUCT_PARITY_DIR \
  HAETAE_C_VERIFICATION_NTT_PARITY_DIR \
  HAETAE_C_VERIFY_ARITHMETIC_PARITY_DIR \
  HAETAE_C_Z1_COMPOSITION_PARITY_DIR \
  HAETAE_DECODER_COEFFICIENT_PARITY_DIR
do
  directory="${!name}"
  test -d "$directory" || {
    echo "MISSING_FIXTURE=$name:$directory"
    exit 1
  }
  echo "$name=PASS"
done

for mode in 2 3 5; do
  test -s "$HAETAE_KEYGEN_KEYPAIR_PARITY_DIR/keypair_mode${mode}.txt"
  test -s "$HAETAE_RANS_PARITY_DIR/rans_mode${mode}.txt"
  test -s "$HAETAE_SIGNING_RETRY_PARITY_DIR/retry_mode${mode}.txt"

  for directory in \
    "$HAETAE_C_VERIFICATION_MATRIX_PARITY_DIR" \
    "$HAETAE_C_VERIFICATION_MATRIX_PRODUCT_PARITY_DIR" \
    "$HAETAE_C_VERIFICATION_NTT_PARITY_DIR" \
    "$HAETAE_C_VERIFY_ARITHMETIC_PARITY_DIR" \
    "$HAETAE_C_Z1_COMPOSITION_PARITY_DIR" \
    "$HAETAE_DECODER_COEFFICIENT_PARITY_DIR"
  do
    test -s "$directory/mode${mode}_case0.json"
  done
done

echo "=== AUTHENTICATED REGRESSION ==="
cargo test -p pqc-rs-haetae --features internal-api

echo "=== STRICT CLIPPY ==="
cargo clippy -p pqc-rs-haetae --all-targets --features internal-api -- -D warnings

echo "=== FORMAT ==="
cargo fmt --all -- --check

echo "=== DIFF INTEGRITY ==="
git diff --check
git diff --cached --check

echo "HAETAE_AUTHENTICATED_REGRESSION_STATUS=PASS"
