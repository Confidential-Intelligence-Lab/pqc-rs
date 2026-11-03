#!/usr/bin/env bash
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-disable-isolation}"

echo "=== HAETAE BOUNDED MIRI ==="

for filter in \
  arithmetic::tests:: \
  montgomery::tests:: \
  ntt::tests::
do
  cargo +nightly miri test \
    -p pqc-rs-haetae \
    --lib \
    "$filter"
done

echo "HAETAE_MIRI_STATUS=PASS"

echo "=== SMAUG-T BOUNDED MIRI ==="

for filter in \
  arithmetic::tests:: \
  encoding::tests:: \
  kem::tests::decapsulation_rejects_invalid_input_lengths
do
  cargo +nightly miri test \
    --manifest-path experimental/pqc-rs-smaug-t/Cargo.toml \
    --lib \
    "$filter"
done

echo "SMAUGT_MIRI_STATUS=PASS"
echo "PQC_EXPERIMENTAL_MIRI_STATUS=PASS"
