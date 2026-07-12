#!/usr/bin/env bash
set -euo pipefail

cargo +nightly fuzz list --fuzz-dir fuzz
