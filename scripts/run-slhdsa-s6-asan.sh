#!/usr/bin/env bash
set -euo pipefail

host="$(rustc -vV | sed -n 's/^host: //p')"

case "${host}" in
  aarch64-apple-darwin|x86_64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "AddressSanitizer is not configured for host ${host}" >&2; exit 2 ;;
esac

export RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"
export RUSTDOCFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:halt_on_error=1:strict_string_checks=1}"

echo "== SLH-DSA library and integration tests under ASan =="

cargo +nightly test \
  -p pqc-rs-slh-dsa \
  --all-features \
  --target "${host}"

echo
echo "SLH-DSA ASan campaign complete."
