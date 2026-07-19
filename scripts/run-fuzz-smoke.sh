#!/usr/bin/env bash
set -euo pipefail

readonly DURATION="${FUZZ_SECONDS:-20}"
readonly DEFAULT_TARGETS=(
  ml_kem_key_checks
  ml_kem_decapsulation
  hpke_vector_parser
  hpke_receiver_open
  hybrid_kem_inputs
  mldsa_primitives
  mldsa_verification
)

if [[ -n "${FUZZ_TARGETS:-}" ]]; then
  read -r -a TARGETS <<<"${FUZZ_TARGETS}"
else
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

for target in "${TARGETS[@]}"; do
  echo "== Fuzz smoke: ${target} (${DURATION}s) =="
  args=(
    +nightly fuzz run
    --fuzz-dir fuzz
    "${target}"
    --
    "-max_total_time=${DURATION}"
    "-timeout=10"
  )

  dictionary="fuzz/dictionaries/${target}.dict"
  if [[ "${target}" == "hpke_vector_parser" ]]; then
    dictionary="fuzz/dictionaries/json.dict"
  fi
  if [[ -f "${dictionary}" ]]; then
    args+=("-dict=${dictionary}")
  fi

  cargo "${args[@]}"
done
