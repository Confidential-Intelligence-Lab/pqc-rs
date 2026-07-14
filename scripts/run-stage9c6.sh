#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-ml-dsa
cargo test --workspace --all-features

if cargo +nightly fuzz --help >/dev/null 2>&1; then
  cargo +nightly fuzz run --fuzz-dir fuzz mldsa_primitives -- -runs=100000 -max_len=256 -timeout=10
else
  echo "cargo-fuzz unavailable; deterministic regression tests completed."
fi
