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
    "$TESTS/reference_gaussian_oracle.c" \
    "$TESTS/reference_arithmetic_oracle.c" \
    "$REF/src/hwt.c" \
    "$REF/src/dg.c" \
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
echo "=== PREPARE EXPERIMENTAL CORRECTED GAUSSIAN REFERENCE ==="
python3 - "$REF/src/dg.c" "$BUILD_DIR/dg_corrected.c" <<'GAUSSIAN_PATCH_PY'
from pathlib import Path
import sys

original = Path(sys.argv[1]).read_text()
old = "out[j] = ((uint64_t)(in[pos + j])) |"
new = "out[i * 10 + j] = ((uint64_t)(in[pos + j])) |"

assert original.count(old) == 1, (
    "STOP: pinned Gaussian source no longer matches expected defect"
)
assert new not in original

Path(sys.argv[2]).write_text(original.replace(old, new, 1))
print("GAUSSIAN_CORRECTED_REFERENCE_PREPARATION=PASS")
GAUSSIAN_PATCH_PY

echo "=== BUILD 28 REFERENCE ORACLES ==="

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
        -ffunction-sections -fdata-sections \
    "-DSMAUGT_REFERENCE_HWT_C=\"$REF/src/hwt.c\"" \
    "-DSMAUGT_REFERENCE_KEY_C=\"$REF/src/key.c\"" \
        -I"$REF/include" \
        "$TESTS/reference_sampling_oracle.c" \
        "$REF/src/fips202.c" \
    -Wl,-dead_strip \
        -o "$BUILD_DIR/sampling-$MODE"

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_gaussian_oracle.c" \
        "$REF/src/dg.c" \
        "$REF/src/fips202.c" \
        -o "$BUILD_DIR/gaussian-original-$MODE"

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_gaussian_oracle.c" \
        "$BUILD_DIR/dg_corrected.c" \
        "$REF/src/fips202.c" \
        -o "$BUILD_DIR/gaussian-corrected-$MODE"
done

echo
# S4.2c: direct C/Rust arithmetic parity integration
echo "=== BUILD ARITHMETIC REFERENCE ORACLES ==="

for ENTRY in \
    "mode1:SMAUGT_MODE1" \
    "mode3:SMAUGT_MODE3" \
    "mode5:SMAUGT_MODE5" \
    "modet:SMAUGT_MODET"
do
    MODE=${ENTRY%%:*}
    CONFIG=${ENTRY#*:}

    clang -std=c11 -O1 -Wall -Wextra -Werror \
        -ffunction-sections -fdata-sections \
        -DSMAUGT_CONFIG_MODE="$CONFIG" \
        -I"$REF/include" \
        "$TESTS/reference_arithmetic_oracle.c" \
        "$REF/src/poly.c" \
        "$REF/src/toomcook.c" \
        -Wl,-dead_strip \
        -o "$BUILD_DIR/arithmetic-$MODE"

    echo "ARITHMETIC_ORACLE_MODE=$MODE STATUS=PASS"
done

# S4.4d: full IND-CPA reference-oracle integration.
echo "=== BUILD EXTENDED IND-CPA REFERENCE ORACLES ==="

mkdir -p "$BUILD_DIR/ephemeral" \
         "$BUILD_DIR/c1" \
         "$BUILD_DIR/c2" \
         "$BUILD_DIR/encrypt" \
         "$BUILD_DIR/decrypt"

for ENTRY in \
    "mode1:SMAUGT_MODE1" \
    "mode3:SMAUGT_MODE3" \
    "mode5:SMAUGT_MODE5" \
    "modet:SMAUGT_MODET"
do
    MODE=${ENTRY%%:*}
    CONFIG=${ENTRY#*:}

    for KIND in keypair ephemeral c1 c2 encrypt decrypt
    do
        case "$KIND" in
            keypair) ORACLE_SOURCE=reference_indcpa_keypair_oracle.c ;;
            ephemeral) ORACLE_SOURCE=reference_ephemeral_oracle.c ;;
            c1) ORACLE_SOURCE=reference_c1_oracle.c ;;
            c2) ORACLE_SOURCE=reference_c2_oracle.c ;;
            encrypt) ORACLE_SOURCE=reference_indcpa_encrypt_oracle.c ;;
            decrypt) ORACLE_SOURCE=reference_indcpa_decrypt_oracle.c ;;
            *) echo "FAIL: unexpected oracle kind" >&2; exit 1 ;;
        esac

        OUTPUT="$BUILD_DIR/$KIND-$MODE"

        clang -std=c11 -O1 -Wall -Wextra -Werror \
            -Wno-error=sign-compare \
            -ffunction-sections -fdata-sections \
            -DSMAUGT_CONFIG_MODE="$CONFIG" \
            -I"$REF/include" \
            "$TESTS/$ORACLE_SOURCE" \
            "$REF/src/key.c" \
            "$REF/src/indcpa.c" \
            "$REF/src/ciphertext.c" \
            "$REF/src/poly.c" \
            "$REF/src/toomcook.c" \
            "$REF/src/pack.c" \
            "$REF/src/packring.c" \
            "$REF/src/fips202.c" \
            "$REF/src/cbd.c" \
            "$REF/src/hwt.c" \
            "$BUILD_DIR/dg_corrected.c" \
            "$REF/src/verify.c" \
            "$REF/src/randombytes.c" \
            -Wl,-dead_strip \
            -o "$OUTPUT"

        test -x "$OUTPUT"

        if [ "$KIND" != keypair ]; then
            "$OUTPUT" > "$BUILD_DIR/$KIND/$KIND-$MODE.txt"
            test -s "$BUILD_DIR/$KIND/$KIND-$MODE.txt"
        fi

        echo "EXTENDED_ORACLE_KIND=$KIND MODE=$MODE STATUS=PASS"
    done
done

echo "S4_4D_EXTENDED_ORACLE_BUILD=PASS"

# S5.5a: native Rust KEM reference interoperability.
echo "=== BUILD KEM REFERENCE ORACLES ==="

mkdir -p "$BUILD_DIR/kem-keypair" \
         "$BUILD_DIR/kem-encapsulation" \
         "$BUILD_DIR/kem-decapsulation"

for ENTRY in \
    "mode1:SMAUGT_MODE1" \
    "mode3:SMAUGT_MODE3" \
    "mode5:SMAUGT_MODE5" \
    "modet:SMAUGT_MODET"
do
    MODE=${ENTRY%%:*}
    CONFIG=${ENTRY#*:}

    for KIND in keypair encapsulation decapsulation
    do
        case "$KIND" in
            keypair)
                ORACLE_SOURCE=reference_kem_keypair_oracle.c
                ;;
            encapsulation)
                ORACLE_SOURCE=reference_kem_encapsulation_oracle.c
                ;;
            decapsulation)
                ORACLE_SOURCE=reference_kem_decapsulation_oracle.c
                ;;
            *)
                echo "FAIL: unexpected KEM oracle kind" >&2
                exit 1
                ;;
        esac

        OUTPUT="$BUILD_DIR/kem-$KIND/kem-$KIND-$MODE"

        clang -std=c11 -O1 -Wall -Wextra -Werror \
            -Wno-error=sign-compare \
            -ffunction-sections -fdata-sections \
            -DSMAUGT_CONFIG_MODE="$CONFIG" \
            -I"$REF/include" \
            "$TESTS/$ORACLE_SOURCE" \
            "$REF/src/kem.c" \
            "$REF/src/key.c" \
            "$REF/src/indcpa.c" \
            "$REF/src/ciphertext.c" \
            "$REF/src/poly.c" \
            "$REF/src/toomcook.c" \
            "$REF/src/pack.c" \
            "$REF/src/packring.c" \
            "$REF/src/fips202.c" \
            "$REF/src/hash.c" \
            "$REF/src/cbd.c" \
            "$REF/src/hwt.c" \
            "$BUILD_DIR/dg_corrected.c" \
            "$REF/src/verify.c" \
            "$REF/src/randombytes.c" \
            -Wl,-dead_strip \
            -o "$OUTPUT"

        test -x "$OUTPUT"

        "$OUTPUT" > "$OUTPUT.txt"
        test -s "$OUTPUT.txt"

        echo "KEM_ORACLE_KIND=$KIND MODE=$MODE STATUS=PASS"
    done
done

echo "S5_5A_KEM_ORACLE_BUILD=PASS"


echo "=== FORMAT CHECK ==="
cargo fmt --manifest-path "$MANIFEST" --check

echo

echo "=== PINNED GAUSSIAN REFERENCE REGRESSION ==="
SMAUGT_GAUSSIAN_ORACLE="$BUILD_DIR/gaussian-original" \
cargo test --manifest-path "$MANIFEST" \
    --test reference_gaussian_parity \
    pinned_reference_gaussian_overwrite_regression \
    -- --exact --ignored

echo "GAUSSIAN_ORIGINAL_REFERENCE_REGRESSION=PASS"

echo "=== COMPLETE RUST AND DIFFERENTIAL TEST SUITE ==="

SMAUGT_PACK_ORACLE="$BUILD_DIR/pack" \
SMAUGT_DECODE_ORACLE="$BUILD_DIR/decode" \
SMAUGT_SECRET_ORACLE="$BUILD_DIR/secret" \
SMAUGT_MATRIX_ORACLE="$BUILD_DIR/matrix" \
SMAUGT_SAMPLING_ORACLE="$BUILD_DIR/sampling" \
SMAUGT_GAUSSIAN_ORACLE="$BUILD_DIR/gaussian-corrected" \
SMAUGT_ARITHMETIC_ORACLE="$BUILD_DIR/arithmetic" \
SMAUGT_KEYPAIR_ORACLE="$BUILD_DIR/keypair" \
SMAUGT_EPHEMERAL_ORACLE="$BUILD_DIR/ephemeral" \
SMAUGT_C1_ORACLE="$BUILD_DIR/c1" \
SMAUGT_C2_ORACLE="$BUILD_DIR/c2" \
SMAUGT_ENCRYPT_ORACLE="$BUILD_DIR/encrypt" \
SMAUGT_DECRYPT_ORACLE="$BUILD_DIR/decrypt" \
SMAUGT_KEM_KEYPAIR_ORACLE="$BUILD_DIR/kem-keypair" \
SMAUGT_KEM_ENCAPSULATION_ORACLE="$BUILD_DIR/kem-encapsulation" \
SMAUGT_KEM_DECAPSULATION_ORACLE="$BUILD_DIR/kem-decapsulation" \
cargo test --manifest-path "$MANIFEST" --lib --tests -- --nocapture

echo
echo "=== CLIPPY ==="
cargo clippy --manifest-path "$MANIFEST" \
    --all-targets -- -D warnings

echo
echo "=== DOCUMENTATION TESTS ==="
cargo test --manifest-path "$MANIFEST" --doc

echo
echo "SMAUGT_REFERENCE_VALIDATION=PASS"
