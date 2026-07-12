#!/usr/bin/env bash
set -euo pipefail

cargo install --locked cargo-fuzz
rustup toolchain install nightly
