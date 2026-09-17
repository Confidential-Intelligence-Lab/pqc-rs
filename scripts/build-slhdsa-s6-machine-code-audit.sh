#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/slhdsa-s6-machine-code}"
mkdir -p "${OUT_DIR}"

if ! rustup component list --installed | grep -q '^llvm-tools'; then
  rustup component add llvm-tools-preview
fi

RUSTFLAGS="-C target-cpu=native -C debuginfo=2 -C force-frame-pointers=yes" \
cargo build \
  -p pqc-rs-test-harness \
  --bin slhdsa-s6-ct-audit \
  --release

BINARY="target/release/slhdsa-s6-ct-audit"

HOST="$(rustc -vV | sed -n 's/^host: //p')"
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="${SYSROOT}/lib/rustlib/${HOST}/bin"
LLVM_OBJDUMP="${LLVM_BIN}/llvm-objdump"
LLVM_NM="${LLVM_BIN}/llvm-nm"

"${LLVM_OBJDUMP}" \
  --macho \
  --demangle \
  --disassemble \
  --no-show-raw-insn \
  "${BINARY}" \
  > "${OUT_DIR}/audit-binary.objdump.txt"

"${LLVM_NM}" \
  --demangle \
  "${BINARY}" \
  > "${OUT_DIR}/audit-binary.nm.txt"

rustc --version --verbose > "${OUT_DIR}/rustc-version.txt"
cargo --version > "${OUT_DIR}/cargo-version.txt"
uname -a > "${OUT_DIR}/system.txt"

echo "Recovered SLH-DSA optimized machine code under ${OUT_DIR}."
