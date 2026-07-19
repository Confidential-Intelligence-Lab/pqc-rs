#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="${PERF_OUT_DIR:-$ROOT/target/performance-baseline}"
mkdir -p "$OUT"

{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_revision=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "git_status=$(git -C "$ROOT" status --porcelain 2>/dev/null | wc -l | tr -d ' ') changed paths"
  echo "uname=$(uname -a)"
  echo "rustc=$(rustc --version --verbose | tr '\n' ';')"
  echo "cargo=$(cargo --version)"
  if command -v sysctl >/dev/null 2>&1; then
    echo "cpu_brand=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
    echo "cpu_count=$(sysctl -n hw.logicalcpu 2>/dev/null || true)"
  fi
  if command -v lscpu >/dev/null 2>&1; then
    echo "lscpu_begin"
    lscpu
    echo "lscpu_end"
  fi
} > "$OUT/environment.txt"

cargo xtask performance-audit --check
cargo bench --bench ml_kem
cargo bench --bench ml_dsa
cargo bench --bench hpke
cargo bench --bench hybrid_hpke

echo "B1.3.5 baseline complete"
echo "Environment: $OUT/environment.txt"
echo "Criterion: $ROOT/target/criterion"
