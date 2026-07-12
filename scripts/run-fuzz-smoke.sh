#!/usr/bin/env bash
set -euo pipefail

readonly DURATION="${FUZZ_SECONDS:-20}"
readonly TARGETS=(
  ml_kem_key_checks
  ml_kem_decapsulation
  hpke_vector_parser
  hpke_receiver_open
  hybrid_kem_inputs
)

for target in "${TARGETS[@]}"; do
  echo "== Fuzz smoke: ${target} (${DURATION}s) =="
  cargo +nightly fuzz run     --fuzz-dir fuzz     "${target}"     --     "-max_total_time=${DURATION}"     "-timeout=10"
done
