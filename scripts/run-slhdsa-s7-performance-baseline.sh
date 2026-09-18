#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT="${PERF_OUT_DIR:-$ROOT/target/slhdsa-s7-performance}"

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
    echo "memory_bytes=$(sysctl -n hw.memsize 2>/dev/null || true)"
  fi

  if command -v lscpu >/dev/null 2>&1; then
    echo "lscpu_begin"
    lscpu
    echo "lscpu_end"
  fi
} > "$OUT/environment.txt"

cargo xtask performance-audit --check

rm -rf "$ROOT/target/criterion"

cargo bench --bench slh_dsa 2>&1 | tee "$OUT/criterion-output.txt"

rm -rf "$OUT/criterion"
cp -R "$ROOT/target/criterion" "$OUT/criterion"

echo "SLH-DSA S7 performance baseline complete"
echo "Environment: $OUT/environment.txt"
echo "Console results: $OUT/criterion-output.txt"
echo "Criterion results: $OUT/criterion"
