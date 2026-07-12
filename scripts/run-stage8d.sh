#!/usr/bin/env bash
set -u

mkdir -p target

status=0

run_check() {
  local label="$1"
  shift

  echo "== ${label} =="

  if ! "$@"; then
    status=1
  fi
}

run_check \
  "Stage 8D: secret inventory" \
  ./scripts/audit-secret-types.sh

run_check \
  "Stage 8D: Debug exposure check" \
  ./scripts/check-secret-debug.sh

run_check \
  "Stage 8D: unsafe-code check" \
  ./scripts/check-unsafe-code.sh

run_check \
  "Stage 8D: secret-dependent branch inventory" \
  ./scripts/check-secret-branches.sh

run_check \
  "Stage 8D: formatting" \
  cargo fmt --all -- --check

run_check \
  "Stage 8D: linting" \
  cargo clippy --workspace --all-targets --all-features -- -D warnings

run_check \
  "Stage 8D: tests" \
  cargo test --workspace --all-features

exit "${status}"
