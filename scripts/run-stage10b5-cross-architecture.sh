#!/usr/bin/env bash
set -euo pipefail

TARGET_ID="${1:-}"

case "${TARGET_ID}" in
  linux-x86_64|linux-aarch64|apple-aarch64) ;;
  *)
    echo "usage: $0 {linux-x86_64|linux-aarch64|apple-aarch64}" >&2
    exit 2
    ;;
esac

POLICY="sidechannel/stage10b5/policy.json"
ROOT_OUT="target/stage10b5"
OUT_DIR="${ROOT_OUT}/${TARGET_ID}"
ARCHIVE="${ROOT_OUT}/stage10b5-${TARGET_ID}-evidence.tar.gz"
PACKAGE_LOG="${ROOT_OUT}/${TARGET_ID}-evidence-package.log"
LOG_DIR="${OUT_DIR}/logs"
MACHINE_DIR="${OUT_DIR}/machine-code"

rm -rf "${OUT_DIR}"
rm -f "${ARCHIVE}" "${PACKAGE_LOG}"
mkdir -p "${LOG_DIR}" "${MACHINE_DIR}"

export CARGO_TERM_COLOR=never

run_logged() {
  local label="$1"
  shift
  "$@" 2>&1 | tee "${LOG_DIR}/${label}.log"
}

run_logged format cargo fmt --all -- --check
run_logged clippy \
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
run_logged tests cargo test --workspace --all-features --locked

rustc --version --verbose > "${OUT_DIR}/rustc-version.txt"
cargo --version > "${OUT_DIR}/cargo-version.txt"
uname -a > "${OUT_DIR}/system.txt"

HOST="$(rustc --version --verbose | sed -n 's/^host: //p')"
SYSROOT="$(rustc --print sysroot)"
LLVM_BIN="${SYSROOT}/lib/rustlib/${HOST}/bin"
LLVM_OBJDUMP="${LLVM_BIN}/llvm-objdump"
LLVM_NM="${LLVM_BIN}/llvm-nm"

if [[ ! -x "${LLVM_OBJDUMP}" || ! -x "${LLVM_NM}" ]]; then
  echo "llvm-tools-preview is required for Stage 10B-5." >&2
  echo "Expected tools below ${LLVM_BIN}." >&2
  exit 1
fi

AUDIT_BINARIES=(
  ct-stage10b11-audit
  ct-stage10b2-audit
  ct-stage10b3-audit
  ct-stage10b4-audit
)

BUILD_COMMAND=(
  cargo build
  --locked
  -p pqc-rs-test-harness
  --release
)

for binary in "${AUDIT_BINARIES[@]}"; do
  BUILD_COMMAND+=(--bin "${binary}")
done

RUSTFLAGS="-C target-cpu=native -C debuginfo=2 -C force-frame-pointers=yes" \
  run_logged audit-build "${BUILD_COMMAND[@]}"

for binary in "${AUDIT_BINARIES[@]}"; do
  executable="target/release/${binary}"
  if [[ ! -x "${executable}" ]]; then
    echo "Audit binary was not created: ${executable}" >&2
    exit 1
  fi

  if [[ "$(uname -s)" == "Darwin" ]]; then
    "${LLVM_OBJDUMP}" \
      --macho \
      --demangle \
      --disassemble \
      --no-show-raw-insn \
      "${executable}" \
      > "${MACHINE_DIR}/${binary}.objdump.txt"
  else
    "${LLVM_OBJDUMP}" \
      --demangle \
      --disassemble \
      --no-show-raw-insn \
      "${executable}" \
      > "${MACHINE_DIR}/${binary}.objdump.txt"
  fi

  "${LLVM_NM}" --demangle "${executable}" \
    > "${MACHINE_DIR}/${binary}.nm.txt"
done

run_logged machine-code-analysis \
  python3 scripts/analyze-stage10b5-machine-code.py \
    --policy "${POLICY}" \
    --target-id "${TARGET_ID}" \
    --objdump-dir "${MACHINE_DIR}" \
    --output "${OUT_DIR}/machine-code.json"

run_logged timing-collection \
  cargo run \
    --locked \
    -p pqc-rs-test-harness \
    --release \
    --bin ct-stage10b2-timing \
    -- "${OUT_DIR}/timing.csv"

TIMING_THRESHOLD="$(
  python3 -c \
    'import json; print(json.load(open("sidechannel/stage10b5/policy.json"))["timing"]["threshold_absolute_welch_t"])'
)"

run_logged timing-analysis \
  python3 scripts/analyze-stage10b5-timing.py \
    "${OUT_DIR}/timing.csv" \
    --threshold "${TIMING_THRESHOLD}" \
    --output "${OUT_DIR}/timing.json"

python3 scripts/package-stage10b5-evidence.py \
  --policy "${POLICY}" \
  --target-id "${TARGET_ID}" \
  --evidence-dir "${OUT_DIR}" \
  --archive "${ARCHIVE}" \
  2>&1 | tee "${PACKAGE_LOG}"
