#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-target/stage10b4}"
mkdir -p "${OUT_DIR}"

if ! rustup component list --installed | grep -q '^llvm-tools'; then
  rustup component add llvm-tools-preview
fi

HOST="$(rustc -vV | sed -n 's/^host: //p')"
SYSROOT="$(rustc --print sysroot)"
LLVM_OBJDUMP="${SYSROOT}/lib/rustlib/${HOST}/bin/llvm-objdump"

RUSTFLAGS="-C target-cpu=native -C debuginfo=2 -C force-frame-pointers=yes" \
cargo build \
  -p pqc-rs-test-harness \
  --bin ct-stage10b4-audit \
  --release

BINARY="target/release/ct-stage10b4-audit"

if [[ "${HOST}" == *"apple-darwin" ]]; then
  "${LLVM_OBJDUMP}" --macho --demangle --disassemble --no-show-raw-insn \
    "${BINARY}" > "${OUT_DIR}/ct-stage10b4-audit.objdump.txt"
else
  "${LLVM_OBJDUMP}" --demangle --disassemble --no-show-raw-insn \
    "${BINARY}" > "${OUT_DIR}/ct-stage10b4-audit.objdump.txt"
fi

grep -n -A80 -B5 \
  "audit_zeroize_bytes\\|audit_zeroize_words\\|audit_secret_drop" \
  "${OUT_DIR}/ct-stage10b4-audit.objdump.txt" \
  > "${OUT_DIR}/zeroization-excerpts.txt" || true

if [[ ! -s "${OUT_DIR}/zeroization-excerpts.txt" ]]; then
  echo "Could not recover zeroization audit wrappers." >&2
  exit 1
fi

if ! grep -Eq "strb|strh|str[[:space:]]|stp" \
  "${OUT_DIR}/zeroization-excerpts.txt"; then
  echo "No store instruction detected in zeroization wrappers." >&2
  exit 1
fi

echo "Stage 10B-4 machine-code zeroization audit passed."
