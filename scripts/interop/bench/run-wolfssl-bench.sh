#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

SRC="$ROOT/scripts/interop/bench/wolfssl_bench.c"
BIN="$ROOT/target/interop/wolfssl_bench"
OUT="$ROOT/target/camera-ready-provider-bench/wolfssl"

PREFIX="${WOLFSSL_PREFIX:-$ROOT/target/interop/wolfssl-install}"
LIB="$PREFIX/lib/libwolfssl.a"

if [[ ! -f "$PREFIX/include/wolfssl/wolfcrypt/wc_mlkem.h" ]]; then
    echo "wolfSSL ML-KEM headers not found under $PREFIX" >&2
    exit 1
fi

if [[ ! -f "$PREFIX/include/wolfssl/wolfcrypt/wc_mldsa.h" ]]; then
    echo "wolfSSL ML-DSA headers not found under $PREFIX" >&2
    exit 1
fi

if [[ ! -f "$LIB" ]]; then
    echo "wolfSSL static library not found: $LIB" >&2
    exit 1
fi

mkdir -p "$(dirname "$BIN")" "$OUT"

"${CC:-cc}" \
    -std=c11 \
    -O3 \
    -Wall \
    -Wextra \
    -Werror \
    -I "$PREFIX/include" \
    "$SRC" \
    "$LIB" \
    -lm \
    -lpthread \
    -framework Security \
    -framework CoreFoundation \
    -o "$BIN"

VERSION="$("$PREFIX/bin/wolfssl-config" --version)"
echo "wolfSSL $VERSION"

for op in \
    kem-keygen \
    kem-encaps \
    kem-decaps \
    dsa-keygen \
    dsa-sign \
    dsa-verify
do
    "$BIN" "$op" > "$OUT/$op.json"
    echo "wrote $OUT/$op.json"
done
