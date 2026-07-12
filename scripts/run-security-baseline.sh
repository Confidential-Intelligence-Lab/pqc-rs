#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

if command -v cargo-audit >/dev/null 2>&1; then
    cargo audit
else
    echo "cargo-audit is not installed; skipping" >&2
fi

if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "cargo-deny is not installed; skipping" >&2
fi
