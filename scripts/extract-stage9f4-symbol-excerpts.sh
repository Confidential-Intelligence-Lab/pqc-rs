#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4}"
REPORT="${OUT_DIR}/symbol-excerpts.txt"
: > "${REPORT}"

for DIRECTORY in "${OUT_DIR}/asm-release" "${OUT_DIR}/asm-debug"; do
  echo "## ${DIRECTORY}" >> "${REPORT}"

  for PATTERN in \
    multiply_challenge \
    sign_prepared \
    verify_with_mu \
    sample_eta_poly \
    sample_in_ball \
    high_bits \
    low_bits
  do
    echo "### ${PATTERN}" >> "${REPORT}"
    grep -RIn -A30 -B5 "${PATTERN}" "${DIRECTORY}" >> "${REPORT}" || true
    echo >> "${REPORT}"
  done
done

echo "Wrote ${REPORT}"
