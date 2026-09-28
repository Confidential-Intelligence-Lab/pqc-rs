#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="1.0.0-rc.1"

echo "PQC-rs ${VERSION} publication sequence"
echo

echo "Stage 1 — core"
echo "  cargo publish -p pqc-rs-core --dry-run"
echo "  cargo publish -p pqc-rs-core"
echo

echo "After pqc-rs-core ${VERSION} is indexed:"
echo
echo "Stage 2 — independent algorithm crates"
echo "  cargo publish -p pqc-rs-ml-kem --dry-run"
echo "  cargo publish -p pqc-rs-ml-kem"
echo
echo "  cargo publish -p pqc-rs-ml-dsa --dry-run"
echo "  cargo publish -p pqc-rs-ml-dsa"
echo
echo "  cargo publish -p pqc-rs-slh-dsa --dry-run"
echo "  cargo publish -p pqc-rs-slh-dsa"
echo

echo "After pqc-rs-ml-kem ${VERSION} is indexed:"
echo
echo "Stage 3 — HPKE"
echo "  cargo publish -p pqc-rs-hpke --dry-run"
echo "  cargo publish -p pqc-rs-hpke"
echo

echo "PQC-Forge and assurance crates are not part of this publication."
