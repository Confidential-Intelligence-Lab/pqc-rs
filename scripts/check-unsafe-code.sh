#!/usr/bin/env bash

set -euo pipefail

mkdir -p target

raw_inventory="target/stage8d-unsafe-inventory.txt"
normalized_inventory="target/stage8d-unsafe-inventory.normalized.txt"
reviewed_inventory="compliance/stage8d-reviewed-unsafe.txt"

grep -RInE \
  --include='*.rs' \
  '(^|[^A-Za-z_])(unsafe[[:space:]]+(fn|impl|trait|extern)|unsafe[[:space:]]*\{)' \
  crates \
  > "${raw_inventory}" || true

sed -E 's/^([^:]+):[0-9]+:/\1:/' \
  "${raw_inventory}" \
  | LC_ALL=C sort \
  > "${normalized_inventory}"

if [[ ! -f "${reviewed_inventory}" ]]; then
  echo "Missing reviewed unsafe inventory: ${reviewed_inventory}" >&2
  exit 1
fi

if ! diff -u "${reviewed_inventory}" "${normalized_inventory}"; then
  echo >&2
  echo "Unsafe-code inventory differs from the reviewed baseline." >&2
  echo "Each change requires line-by-line review and a documented SAFETY invariant." >&2
  exit 1
fi

if [[ -s "${raw_inventory}" ]]; then
  cat "${raw_inventory}"
  echo
  echo "All unsafe constructs match the reviewed Stage 8D inventory."
else
  echo "No unsafe code found in workspace crates."
fi
