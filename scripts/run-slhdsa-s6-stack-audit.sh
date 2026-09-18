#!/usr/bin/env bash

set -euo pipefail

OUT_DIR="${1:-target/slhdsa-s6-stack-audit}"
mkdir -p "${OUT_DIR}"

HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"

case "${HOST}" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *)
    echo "SLH-DSA stack-size audit requires a Linux ELF host; got ${HOST}" >&2
    exit 2
    ;;
esac

SYSROOT="$(rustc +nightly --print sysroot)"
LLVM_BIN="${SYSROOT}/lib/rustlib/${HOST}/bin"
LLVM_READOBJ="${LLVM_BIN}/llvm-readobj"
LLVM_NM="${LLVM_BIN}/llvm-nm"

if [[ ! -x "${LLVM_READOBJ}" || ! -x "${LLVM_NM}" ]]; then
  rustup +nightly component add llvm-tools-preview
fi

RUSTFLAGS="-Z emit-stack-sizes -C force-frame-pointers=yes -C debuginfo=2" \
cargo +nightly build \
  -p pqc-rs-test-harness \
  --bin slhdsa-s6-stack-audit \
  --release

BINARY="target/release/slhdsa-s6-stack-audit"

"${LLVM_READOBJ}" \
  --stack-sizes \
  "${BINARY}" \
  > "${OUT_DIR}/stack-sizes.txt"

"${LLVM_NM}" \
  --demangle \
  "${BINARY}" \
  > "${OUT_DIR}/symbols.txt"

rustc +nightly --version --verbose > "${OUT_DIR}/rustc-version.txt"
cargo +nightly --version > "${OUT_DIR}/cargo-version.txt"
uname -a > "${OUT_DIR}/system.txt"

if ! grep -Eq 'pqc_slh_dsa.*fors.*node|pqc_slh_dsa.*xmss.*node' \
  "${OUT_DIR}/stack-sizes.txt"
then
  echo "failed to recover FORS/XMSS node stack-size records" >&2
  exit 1
fi

echo
echo "===== SLH-DSA RECOVERED STACK-SIZE RECORDS ====="

grep -E -A4 -B4 \
  'pqc_slh_dsa.*fors.*node|pqc_slh_dsa.*xmss.*node' \
  "${OUT_DIR}/stack-sizes.txt"

echo
echo "===== SLH-DSA RELATED SYMBOLS ====="

grep -E \
  'pqc_slh_dsa.*(fors|xmss).*node' \
  "${OUT_DIR}/symbols.txt" \
  || true

echo

echo "SLH-DSA stack-size audit complete."
