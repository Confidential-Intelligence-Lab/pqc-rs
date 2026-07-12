#!/usr/bin/env bash
set -euo pipefail
rustup toolchain install nightly --component miri --component rust-src
cargo +nightly miri setup
