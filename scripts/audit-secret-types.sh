#!/usr/bin/env bash
set -euo pipefail

echo "== Secret-bearing type inventory =="

patterns='secret|private_key|private key|decapsulation_key|shared_secret|seed|nonce|randomness'

grep -RInE \
  --include='*.rs' \
  "${patterns}" \
  crates \
  | grep -Ev '/target/|/tests?/|test_vectors|vector|fixture|expected|public_key' \
  > target/stage8d-secret-inventory.txt || true

cat target/stage8d-secret-inventory.txt

echo
echo "Inventory written to target/stage8d-secret-inventory.txt"
