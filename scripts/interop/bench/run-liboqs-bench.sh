#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/scripts/interop/bench/liboqs_bench.c"
BIN="$ROOT/target/interop/liboqs_bench"
OUT="$ROOT/target/camera-ready-provider-bench/liboqs"

if [[ -n "${OQS_PREFIX:-}" ]]; then
    PREFIX="$OQS_PREFIX"
elif [[ -n "${OQS_LIBOQS_PATH:-}" ]]; then
    PREFIX="$(cd "$(dirname "$OQS_LIBOQS_PATH")/.." && pwd)"
elif [[ -f /opt/homebrew/include/oqs/oqs.h ]]; then
    PREFIX="/opt/homebrew"
else
    PREFIX="/usr/local"
fi

mkdir -p "$(dirname "$BIN")" "$OUT"

"${CC:-cc}" \
    -std=c11 \
    -O3 \
    "$SRC" \
    -I "$PREFIX/include" \
    -L "$PREFIX/lib" \
    "-Wl,-rpath,$PREFIX/lib" \
    -loqs \
    -o "$BIN"

for op in kem-keygen kem-encaps kem-decaps; do
    "$BIN" "$op" > "$OUT/$op.json"
    echo "wrote $OUT/$op.json"
done
