#!/usr/bin/env bash
set -euo pipefail

STAGE9F4C_DIR="${1:-target/stage9f4c}"
OUT_DIR="${2:-target/stage9f4d}"
AUDIT_DIR="audit/stage9f4d"

mkdir -p "${OUT_DIR}" "${AUDIT_DIR}"

FLAGGED="${STAGE9F4C_DIR}/flagged-instructions.md"
if [[ ! -f "${FLAGGED}" ]]; then
  echo "Missing ${FLAGGED}; run Stage 9F-4C first." >&2
  exit 1
fi

python3 scripts/stage9f4d-classify.py init   "${FLAGGED}"   "${AUDIT_DIR}/instruction-classification.csv"   "${OUT_DIR}/instruction-classification.md"

python3 scripts/stage9f4d-source-map.py   crates/pqc-ml-dsa/src   "${OUT_DIR}/source-location-candidates.md"

cp "${STAGE9F4C_DIR}/audit-summary.md"   "${OUT_DIR}/stage9f4c-audit-summary.md"
cp "${FLAGGED}"   "${OUT_DIR}/stage9f4c-flagged-instructions.md"

echo "Stage 9F-4D initialized."
echo "Edit ${AUDIT_DIR}/instruction-classification.csv"
echo "Then run ./scripts/validate-stage9f4d-classification.sh"
