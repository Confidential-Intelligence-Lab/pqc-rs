#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SRC="$ROOT/scripts/interop/bench/openssl_dsa_bench.c"
BIN="$ROOT/target/interop/openssl_dsa_bench"
OUT="$ROOT/target/camera-ready-provider-bench/openssl-dsa"

if [[ -n "${OPENSSL_PREFIX:-}" ]]; then
    PREFIX="$OPENSSL_PREFIX"
elif command -v brew >/dev/null 2>&1; then
    PREFIX="$(brew --prefix openssl@3)"
elif [[ -d /opt/homebrew/opt/openssl@3 ]]; then
    PREFIX="/opt/homebrew/opt/openssl@3"
elif [[ -d /usr/local/opt/openssl@3 ]]; then
    PREFIX="/usr/local/opt/openssl@3"
else
    echo "OpenSSL 3 prefix not found" >&2
    exit 1
fi

mkdir -p "$(dirname "$BIN")" "$OUT"

"${CC:-cc}" \
    -std=c11 \
    -O3 \
    "$SRC" \
    -I "$PREFIX/include" \
    -L "$PREFIX/lib" \
    "-Wl,-rpath,$PREFIX/lib" \
    -lcrypto \
    -o "$BIN"

"$PREFIX/bin/openssl" version

for op in dsa-keygen dsa-sign dsa-verify; do
    "$BIN" "$op" > "$OUT/$op.json"
    echo "wrote $OUT/$op.json"
done
