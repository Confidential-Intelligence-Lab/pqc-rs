#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check-release-metadata.py

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
cargo audit

cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-keygen --release
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-encapsulation --release
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-decapsulation --release
cargo run -p pqc-rs-test-harness --bin ml-kem-acvp-key-check --release
cargo run -p pqc-rs-test-harness --bin hpke-pq-base-vectors --release
cargo run -p pqc-rs-test-harness --bin hpke-pq-hybrid-vectors --release

cargo package -p pqc-rs-core
cargo package -p pqc-rs-ml-kem --no-verify
cargo package -p pqc-rs-hpke --no-verify

echo "Stage 8 release gate passed."
