#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

SRC="$ROOT/scripts/interop/bench/awslc_bench.c"
BIN="$ROOT/target/interop/awslc_bench"
OUT="$ROOT/target/camera-ready-provider-bench/awslc"

AWS_SRC="${AWSLC_SRC:-$ROOT/target/interop/aws-lc-src}"
PREFIX="${AWSLC_PREFIX:-$ROOT/target/interop/aws-lc-install}"
LIB="$PREFIX/lib/libcrypto.a"

if [[ ! -f "$AWS_SRC/crypto/fipsmodule/ml_kem/ml_kem.h" ]]; then
    echo "AWS-LC ML-KEM header not found under $AWS_SRC" >&2
    exit 1
fi

if [[ ! -f "$LIB" ]]; then
    echo "AWS-LC static libcrypto not found: $LIB" >&2
    exit 1
fi

mkdir -p "$(dirname "$BIN")" "$OUT"

"${CC:-cc}" \
    -std=c11 \
    -O3 \
    -Wall \
    -Wextra \
    -Werror \
    -I "$AWS_SRC" \
    -I "$PREFIX/include" \
    "$SRC" \
    "$LIB" \
    -lpthread \
    -framework Security \
    -framework CoreFoundation \
    -o "$BIN"

echo "AWS-LC revision: $(git -C "$AWS_SRC" rev-parse HEAD)"
echo "AWS-LC describe: $(git -C "$AWS_SRC" describe --tags --always --dirty)"

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
