#!/usr/bin/env bash
set -euo pipefail

INPUT="${1:-audit/stage9f4d/instruction-classification.csv}"
AUDIT_DIR="audit/stage9f4e"
OUT_DIR="${2:-target/stage9f4e}"

mkdir -p "${AUDIT_DIR}" "${OUT_DIR}"

if [[ ! -f "${INPUT}" ]]; then
  echo "Missing ${INPUT}; complete Stage 9F-4D first." >&2
  exit 1
fi

python3 scripts/build-stage9f4e-finding-register.py \
  "${INPUT}" \
  "${AUDIT_DIR}/security-finding-register.csv" \
  "${AUDIT_DIR}/security-finding-register.md" \
  "${OUT_DIR}/stage9f4e-audit-summary.md"

cp "${AUDIT_DIR}/security-finding-register.md" \
  "${OUT_DIR}/security-finding-register.md"

echo "Stage 9F-4E security finding register generated."
