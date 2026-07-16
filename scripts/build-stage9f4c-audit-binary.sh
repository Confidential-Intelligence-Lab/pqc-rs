#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage9f4c}"
mkdir -p "${OUT_DIR}"

if ! rustup component list --installed | grep -q '^llvm-tools'; then
  rustup component add llvm-tools-preview
fi

if ! command -v cargo-objdump >/dev/null 2>&1; then
  echo "cargo-binutils is required." >&2
  echo "Install with: cargo install cargo-binutils" >&2
  exit 1
fi

RUSTFLAGS="-C target-cpu=native -C debuginfo=2 -C force-frame-pointers=yes" \
cargo build \
  -p pqc-rs-test-harness \
  --bin mldsa-stage9f4c-audit \
  --release

BINARY="target/release/mldsa-stage9f4c-audit"

if [[ ! -x "${BINARY}" ]]; then
  echo "Audit binary was not created: ${BINARY}" >&2
  exit 1
fi

HOST="$(rustc -vV | sed -n 's/^host: //p')"
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="${SYSROOT}/lib/rustlib/${HOST}/bin"
LLVM_OBJDUMP="${LLVM_BIN}/llvm-objdump"
LLVM_NM="${LLVM_BIN}/llvm-nm"

if [[ ! -x "${LLVM_OBJDUMP}" ]]; then
  echo "llvm-objdump not found at ${LLVM_OBJDUMP}" >&2
  echo "Run: rustup component add llvm-tools-preview" >&2
  exit 1
fi

if [[ ! -x "${LLVM_NM}" ]]; then
  echo "llvm-nm not found at ${LLVM_NM}" >&2
  echo "Run: rustup component add llvm-tools-preview" >&2
  exit 1
fi

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

echo "Recovered optimized machine code under ${OUT_DIR}."
