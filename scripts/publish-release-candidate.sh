#!/usr/bin/env bash
set -euo pipefail

echo "Dry-run core"
cargo publish -p pqc-rs-core --dry-run

echo "Publish core when ready:"
echo "  cargo publish -p pqc-rs-core"
echo
echo "After crates.io indexes pqc-rs-core 0.4.0:"
echo "  cargo publish -p pqc-rs-ml-kem --dry-run"
echo "  cargo publish -p pqc-rs-ml-kem"
echo
echo "After crates.io indexes pqc-rs-ml-kem 0.4.0:"
echo "  cargo publish -p pqc-rs-hpke --dry-run"
echo "  cargo publish -p pqc-rs-hpke"
