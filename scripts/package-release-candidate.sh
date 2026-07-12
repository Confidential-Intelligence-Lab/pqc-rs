#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="0.4.0-rc.1"
readonly OUT_DIR="target/release-candidate"

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}"/*.crate
rm -f "${OUT_DIR}"/*.tar.gz
rm -f "${OUT_DIR}"/*-file-list.txt
rm -f "${OUT_DIR}/build-record.txt"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "The working tree is not clean." >&2
  echo "Commit the release changes before creating the release candidate." >&2
  git status --short >&2
  exit 1
fi

echo "== Validate local release crates =="
cargo check -p pqc-core --all-features
cargo check -p pqc-ml-kem --all-features
cargo check -p pqc-hpke --all-features

echo "== Fully package and verify pqc-core =="
cargo package -p pqc-core --list \
  > "${OUT_DIR}/pqc-core-file-list.txt"

cargo package -p pqc-core

cp \
  "target/package/pqc-core-${VERSION}.crate" \
  "${OUT_DIR}/"

echo "== Record tracked files for dependent crates =="

git ls-files \
  crates/pqc-ml-kem \
  README.md \
  LICENSE \
  LICENSE-MIT \
  LICENSE-APACHE \
  2>/dev/null \
  | sort -u \
  > "${OUT_DIR}/pqc-ml-kem-file-list.txt"

git ls-files \
  crates/pqc-hpke \
  README.md \
  LICENSE \
  LICENSE-MIT \
  LICENSE-APACHE \
  2>/dev/null \
  | sort -u \
  > "${OUT_DIR}/pqc-hpke-file-list.txt"

echo "== Create complete source archive =="

git archive \
  --format=tar.gz \
  --prefix="pqc-rs-${VERSION}/" \
  -o "${OUT_DIR}/pqc-rs-${VERSION}.tar.gz" \
  HEAD

echo "== Record build metadata =="

{
  date -u
  rustc -Vv
  cargo -V
  git rev-parse HEAD
  git status --short
} > "${OUT_DIR}/build-record.txt"

cat <<SUMMARY

Release candidate artifacts created in:

  ${OUT_DIR}/

Artifacts:
  pqc-core-${VERSION}.crate
  pqc-rs-${VERSION}.tar.gz
  pqc-core-file-list.txt
  pqc-ml-kem-file-list.txt
  pqc-hpke-file-list.txt
  build-record.txt

The dependent crates cannot be registry-verified before their internal
dependencies are published.

Required publication order:

  1. pqc-core
  2. pqc-ml-kem
  3. pqc-hpke

SUMMARY
