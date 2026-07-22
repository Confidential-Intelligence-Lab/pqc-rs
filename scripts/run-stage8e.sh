#!/usr/bin/env bash
set -euo pipefail
mkdir -p target/stage8e
{ date -u; rustc -Vv; cargo -V; uname -a; } > target/stage8e/environment.txt
python3 scripts/report-crypto-sizes.py | tee target/stage8e/sizes.md
cargo bench --bench ml_kem | tee target/stage8e/ml-kem-bench.txt
cargo bench --bench hpke | tee target/stage8e/hpke-bench.txt
cargo bench --bench hybrid_hpke | tee target/stage8e/hybrid-hpke-bench.txt
cargo build --workspace --release
find target/release -maxdepth 1 -type f -perm -111 -exec ls -lh {} \; | tee target/stage8e/release-binaries.txt
echo 'Stage 8E reports written to target/stage8e/'

cargo bench -p pqc-rs-ml-kem --bench ml_kem \
  | tee target/stage8e/ml-kem-bench.txt

cargo bench -p pqc-rs-hpke --bench hpke \
  | tee target/stage8e/hpke-bench.txt

cargo bench -p pqc-rs-hpke --bench hybrid_hpke \
  | tee target/stage8e/hybrid-hpke-bench.txt
