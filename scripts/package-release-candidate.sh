#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="0.4.0"
readonly OUT_DIR="target/release-candidate"

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}"/*.crate "${OUT_DIR}"/*.tar.gz 2>/dev/null || true

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit before packaging." >&2
  git status --short >&2
  exit 1
fi

cargo check -p pqc-rs-core --all-features
cargo check -p pqc-rs-ml-kem --all-features
cargo check -p pqc-rs-hpke --all-features

cargo package -p pqc-rs-core --list \
  > "${OUT_DIR}/pqc-rs-core-package-list.txt"
cargo package -p pqc-rs-core

cp "target/package/pqc-rs-core-${VERSION}.crate" "${OUT_DIR}/"

git ls-files crates/pqc-rs-ml-kem README.md LICENSE LICENSE-MIT LICENSE-APACHE \
  2>/dev/null | sort -u > "${OUT_DIR}/pqc-rs-ml-kem-file-list.txt"

git ls-files crates/pqc-rs-hpke README.md LICENSE LICENSE-MIT LICENSE-APACHE \
  2>/dev/null | sort -u > "${OUT_DIR}/pqc-rs-hpke-file-list.txt"

git archive \
  --format=tar.gz \
  --prefix="pqc-rs-${VERSION}/" \
  -o "${OUT_DIR}/pqc-rs-${VERSION}.tar.gz" \
  HEAD

{
  date -u
  rustc -Vv
  cargo -V
  git rev-parse HEAD
  git status --short
} > "${OUT_DIR}/build-record.txt"

echo "Release candidate artifacts written to ${OUT_DIR}/"
echo "Publish order:"
echo "  1. pqc-rs-core"
echo "  2. pqc-rs-ml-kem"
echo "  3. pqc-rs-hpke"
