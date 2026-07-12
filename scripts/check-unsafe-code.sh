#!/usr/bin/env bash
set -euo pipefail

mkdir -p target

grep -RInE \
  --include='*.rs' \
  '(^|[^A-Za-z_])(unsafe[[:space:]]+(fn|impl|trait|extern)|unsafe[[:space:]]*\{)' \
  crates \
  > target/stage8d-unsafe-inventory.txt || true

if [[ -s target/stage8d-unsafe-inventory.txt ]]; then
  cat target/stage8d-unsafe-inventory.txt
  echo
  echo "Unsafe code requires line-by-line review and a documented safety invariant." >&2
  exit 1
fi

echo "No unsafe code found in workspace crates."
