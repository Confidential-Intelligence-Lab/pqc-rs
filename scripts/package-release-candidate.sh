#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="1.0.0-rc.1"
readonly OUT_DIR="target/release-candidate"

readonly PACKAGES=(
  pqc-rs-core
  pqc-rs-ml-kem
  pqc-rs-ml-dsa
  pqc-rs-slh-dsa
  pqc-rs-hpke
)

mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}"/*.crate "${OUT_DIR}"/*.tar.gz 2>/dev/null || true

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit before packaging." >&2
  git status --short >&2
  exit 1
fi

for package in "${PACKAGES[@]}"; do
  cargo check -p "${package}" --all-features
done

for package in "${PACKAGES[@]}"; do
  cargo package -p "${package}" --list \
    > "${OUT_DIR}/${package}-package-list.txt"

  cargo package -p "${package}" --no-verify

  cp \
    "target/package/${package}-${VERSION}.crate" \
    "${OUT_DIR}/"
done

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
echo
echo "Registry publication order:"
echo "  1. pqc-rs-core"
echo "  2. pqc-rs-ml-kem, pqc-rs-ml-dsa, pqc-rs-slh-dsa"
echo "  3. pqc-rs-hpke"
