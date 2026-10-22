#!/bin/bash
# SPDX-License-Identifier: MIT
# Reproducible differential validation against pinned SMAUG-T C reference.

set -e
set -o pipefail

EXPECTED_COMMIT=bbc463cd788eae36c6d155cef667ac9dbd9054cd

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/SMAUG-T/reference_implementation" >&2
    exit 2
fi

REF=$(cd "$1" && pwd -P)

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
CRATE_DIR=$(cd "$SCRIPT_DIR/.." && pwd -P)
MANIFEST="$CRATE_DIR/Cargo.toml"
TESTS="$CRATE_DIR/tests"

for FILE in \
    "$REF/include/params.h" \
    "$REF/include/pack.h" \
    "$REF/include/packring.h" \
    "$REF/src/pack.c" \
    "$REF/src/packring.c" \
    "$TESTS/reference_pack_oracle.c" \
    "$TESTS/reference_decode_oracle.c" \
    "$TESTS/reference_secret_oracle.c" \
    "$TESTS/reference_matrix_oracle.c" \
    "$TESTS/reference_sampling_oracle.c" \
    "$REF/src/hwt.c" \
    "$REF/src/fips202.c"
do
    if [ ! -f "$FILE" ]; then
        echo "FAIL: missing required file: $FILE" >&2
        exit 1
    fi
done

for TOOL in clang cargo rustc git shasum; do
    if ! command -v "$TOOL" >/dev/null 2>&1; then
        echo "FAIL: required tool unavailable: $TOOL" >&2
        exit 1
    fi
done

# A historical source archive may not contain its .git directory.
# Therefore record source hashes even when a Git commit is unavailable.
echo "=== REFERENCE IDENTITY ==="
echo "EXPECTED_UPSTREAM_COMMIT=$EXPECTED_COMMIT"
echo "REFERENCE_DIRECTORY=$REF"

if git -C "$REF" rev-parse --is-inside-work-tree \
    >/dev/null 2>&1
then
    ACTUAL_COMMIT=$(git -C "$REF" rev-parse HEAD)
    echo "REFERENCE_GIT_HEAD=$ACTUAL_COMMIT"

    if [ "$ACTUAL_COMMIT" != "$EXPECTED_COMMIT" ]; then
        echo "FAIL: reference commit mismatch" >&2
        exit 1
    fi
else
    echo "REFERENCE_GIT_HEAD=UNAVAILABLE_ARCHIVE"
    echo "REFERENCE_COMMIT_VERIFIED=NO"
fi

echo
echo "=== SOURCE HASHES ==="
shasum -a 256 \
    "$REF/include/config.h" \
    "$REF/include/params.h" \
    "$REF/src/pack.c" \
    "$REF/src/packring.c"

echo
echo "=== TOOLCHAIN ==="
clang --version | head -1
rustc --version
cargo --version

BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/smaugt-validation.XXXXXXXX")

cleanup() {
    rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

echo
echo "=== BUILD 20 REFERENCE ORACLES ==="

for ENTRY in \
    "mode1:SMAUGT_MODE1" \
    "mode3:SMAUGT_MODE3" \
    "mode5:SMAUGT_MODE5" \
    "modet:SMAUGT_MODET"
do
    MODE=${ENTRY%%:*}
    CONFIG=${ENTRY#*:}

    echo "Building $MODE"

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_pack_oracle.c" \
        "$REF/src/packring.c" \
        -o "$BUILD_DIR/pack-$MODE"

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_decode_oracle.c" \
        "$REF/src/packring.c" \
        -o "$BUILD_DIR/decode-$MODE"

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -ffunction-sections -fdata-sections \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_secret_oracle.c" \
        "$REF/src/pack.c" \
        "$REF/src/packring.c" \
        -Wl,-dead_strip \
        -o "$BUILD_DIR/secret-$MODE"

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_matrix_oracle.c" \
        "$REF/src/packring.c" \
        "$REF/src/fips202.c" \
        -o "$BUILD_DIR/matrix-$MODE"

    # The pinned upstream hwt.c has an int/size_t comparison warning.
    # Preserve -Werror for all other warnings without modifying upstream.
    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -Wno-error=sign-compare \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        "-DSMAUGT_REFERENCE_HWT_C=\"$REF/src/hwt.c\"" \
        -I"$REF/include" \
        "$TESTS/reference_sampling_oracle.c" \
        "$REF/src/fips202.c" \
        -o "$BUILD_DIR/sampling-$MODE"
done

echo
echo "=== FORMAT CHECK ==="
cargo fmt --manifest-path "$MANIFEST" --check

echo
echo "=== COMPLETE RUST AND DIFFERENTIAL TEST SUITE ==="

SMAUGT_PACK_ORACLE="$BUILD_DIR/pack" \
SMAUGT_DECODE_ORACLE="$BUILD_DIR/decode" \
SMAUGT_SECRET_ORACLE="$BUILD_DIR/secret" \
SMAUGT_MATRIX_ORACLE="$BUILD_DIR/matrix" \
SMAUGT_SAMPLING_ORACLE="$BUILD_DIR/sampling" \
cargo test --manifest-path "$MANIFEST" --all-targets

echo
echo "=== CLIPPY ==="
cargo clippy --manifest-path "$MANIFEST" \
    --all-targets -- -D warnings

echo
echo "=== DOCUMENTATION TESTS ==="
cargo test --manifest-path "$MANIFEST" --doc

echo
echo "SMAUGT_REFERENCE_VALIDATION=PASS"
