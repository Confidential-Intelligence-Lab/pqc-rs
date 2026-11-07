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
  slhdsa_verification
  haetae_signature_structure
  haetae_verify_combined
  haetae_verify_public_key
  haetae_verify_signature
  kem_decapsulate
  kem_encapsulate
  secret_decode
)

if [[ -n "${FUZZ_TARGETS:-}" ]]; then
  read -r -a TARGETS <<<"${FUZZ_TARGETS}"
else
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

for target in "${TARGETS[@]}"; do
  case "${target}" in
    haetae_signature_structure|haetae_verify_combined|haetae_verify_public_key|haetae_verify_signature)
      fuzz_dir="crates/pqc-haetae/fuzz"
      ;;
    kem_decapsulate|kem_encapsulate|secret_decode)
      fuzz_dir="crates/pqc-smaug-t/fuzz"
      ;;
    *)
      fuzz_dir="fuzz"
      ;;
  esac

  test -f "${fuzz_dir}/fuzz_targets/${target}.rs" || {
    echo "FAIL: missing fuzz target ${fuzz_dir}/fuzz_targets/${target}.rs" >&2
    exit 1
  }

  echo "== Fuzz smoke: ${target} (${DURATION}s), workspace=${fuzz_dir} =="
  args=(
    +nightly fuzz run
    --fuzz-dir "${fuzz_dir}"
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
