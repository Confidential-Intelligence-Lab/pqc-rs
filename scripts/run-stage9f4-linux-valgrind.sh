#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4-ctgrind}"
mkdir -p "${OUT_DIR}"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind is required for this Linux-only step" >&2
  exit 1
fi

cargo build \
  -p pqc-rs-test-harness \
  --bin mldsa-signing-rejection-trace

BINARY="target/debug/mldsa-signing-rejection-trace"

valgrind \
  --tool=memcheck \
  --track-origins=yes \
  --error-exitcode=99 \
  --log-file="${OUT_DIR}/valgrind.log" \
  "${BINARY}" "${OUT_DIR}/trace.csv"

echo "Valgrind run complete. Review ${OUT_DIR}/valgrind.log."
echo "For strict secret-taint checking, integrate ctgrind annotations in Stage 9F-4B."
