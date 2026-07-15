#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f1}"
mkdir -p "${OUT_DIR}"

{
  echo "# Stage 9F-1 source audit inventory"
  echo
  echo "## Branches and loops"
  grep -RInE '(^|[[:space:]])(if|match|while|for)[[:space:]]' \
    crates/pqc-ml-dsa/src || true
  echo
  echo "## Indexing and table access"
  grep -RInE '\[[^]]+\]|get\(|get_unchecked|swap|sort' \
    crates/pqc-ml-dsa/src || true
  echo
  echo "## Division and remainder"
  grep -RInE ' / | % |div_|rem_|rem_euclid' \
    crates/pqc-ml-dsa/src || true
  echo
  echo "## Unsafe code"
  grep -RIn 'unsafe' crates/pqc-ml-dsa/src || true
} > "${OUT_DIR}/source-audit-inventory.txt"

echo "Wrote ${OUT_DIR}/source-audit-inventory.txt"
