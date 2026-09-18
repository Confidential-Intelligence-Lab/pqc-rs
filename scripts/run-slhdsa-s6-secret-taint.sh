#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/slhdsa-s6-secret-taint}"
mkdir -p "${OUT_DIR}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "SLH-DSA secret-taint audit is Linux-only." >&2
  exit 1
fi

if ! command -v valgrind >/dev/null 2>&1; then
  echo "valgrind is required" >&2
  exit 1
fi

cargo build \
  -p pqc-rs-test-harness \
  --features valgrind-secret-taint \
  --bin slhdsa-s6-secret-taint

BINARY="target/debug/slhdsa-s6-secret-taint"

echo "== positive control =="

set +e
valgrind \
  --tool=memcheck \
  --track-origins=yes \
  --error-exitcode=99 \
  --log-file="${OUT_DIR}/positive-control.log" \
  "${BINARY}" positive-control
POSITIVE_RC=$?
set -e

if [[ "${POSITIVE_RC}" -ne 99 ]]; then
  echo "FAIL: positive control did not trigger Valgrind as expected." >&2
  echo "exit code: ${POSITIVE_RC}" >&2
  exit 1
fi

echo "PASS: positive control triggered Valgrind."

for MODE in \
  shake-prf \
  shake-prf-msg \
  sha2-prf \
  sha2-prf-msg-32 \
  sha2-prf-msg-16
do
  echo "== ${MODE} =="

  valgrind \
    --tool=memcheck \
    --track-origins=yes \
    --error-exitcode=99 \
    --log-file="${OUT_DIR}/${MODE}.log" \
    "${BINARY}" "${MODE}"

  echo "PASS: ${MODE}"
done

{
  echo "# SLH-DSA S6 secret-taint audit"
  echo
  echo "- positive control: detected"
  echo "- SHAKE PRF: pass"
  echo "- SHAKE PRF_msg: pass"
  echo "- SHA2 PRF: pass"
  echo "- SHA2 PRF_msg n=32: pass"
  echo "- SHA2 PRF_msg n=16: pass"
} > "${OUT_DIR}/summary.md"

echo
echo "SLH-DSA S6 secret-taint audit complete."
echo "Artifacts: ${OUT_DIR}"
