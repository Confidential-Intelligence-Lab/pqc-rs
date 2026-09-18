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

# Exercise workspace crates under their complete feature sets, except the
# test harness and SLH-DSA. The test harness valgrind-secret-taint feature
# deliberately requires Valgrind headers and belongs to the independent
# Linux secret-taint gate. SLH-DSA has a dedicated bounded AddressSanitizer
# campaign in run-slhdsa-s6-asan.sh; excluding its exhaustive suites here
# avoids duplicating the same assurance scope in the broad workspace gate.
cargo +nightly test \
  --workspace \
  --all-features \
  --exclude pqc-rs-test-harness \
  --exclude pqc-rs-slh-dsa \
  --target "${host}"

# Exercise the test harness under all ordinary assurance features while
# deliberately excluding the Valgrind-only secret-taint feature.
cargo +nightly test \
  -p pqc-rs-test-harness \
  --features std,alloc,acvp,bench \
  --target "${host}"

cargo +nightly test \
  -p pqc-rs-hpke \
  --test security_negative \
  --all-features \
  --target "${host}"
