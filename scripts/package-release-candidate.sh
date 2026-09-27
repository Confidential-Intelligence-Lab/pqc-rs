#!/usr/bin/env bash
set -euo pipefail

readonly VERSION="1.0.0-rc.1"
readonly OUT_DIR="target/release-candidate"

usage() {
  cat <<USAGE
Usage:
  $0 core
  $0 algorithms
  $0 hpke

Stages:
  core
      Package pqc-rs-core and create the source archive/build record.

  algorithms
      Package pqc-rs-ml-kem, pqc-rs-ml-dsa, and pqc-rs-slh-dsa.
      Run only after pqc-rs-core ${VERSION} is published and indexed.

  hpke
      Package pqc-rs-hpke.
      Run only after pqc-rs-ml-kem ${VERSION} is published and indexed.
USAGE
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

readonly STAGE="$1"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit before packaging." >&2
  git status --short >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

package_one() {
  local package="$1"

  echo
  echo "=== CHECK ${package} ==="
  cargo check -p "${package}" --all-features

  echo
  echo "=== PACKAGE LIST ${package} ==="
  cargo package -p "${package}" --list \
    > "${OUT_DIR}/${package}-package-list.txt"

  echo
  echo "=== PACKAGE ${package} ==="
  cargo package -p "${package}" --no-verify

  cp \
    "target/package/${package}-${VERSION}.crate" \
    "${OUT_DIR}/"
}

case "${STAGE}" in
  core)
    rm -f \
      "${OUT_DIR}/pqc-rs-core-${VERSION}.crate" \
      "${OUT_DIR}/pqc-rs-core-package-list.txt" \
      "${OUT_DIR}/pqc-rs-${VERSION}.tar.gz" \
      "${OUT_DIR}/build-record.txt"

    package_one pqc-rs-core

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
    ;;

  algorithms)
    rm -f \
      "${OUT_DIR}/pqc-rs-ml-kem-${VERSION}.crate" \
      "${OUT_DIR}/pqc-rs-ml-dsa-${VERSION}.crate" \
      "${OUT_DIR}/pqc-rs-slh-dsa-${VERSION}.crate" \
      "${OUT_DIR}/pqc-rs-ml-kem-package-list.txt" \
      "${OUT_DIR}/pqc-rs-ml-dsa-package-list.txt" \
      "${OUT_DIR}/pqc-rs-slh-dsa-package-list.txt"

    package_one pqc-rs-ml-kem
    package_one pqc-rs-ml-dsa
    package_one pqc-rs-slh-dsa
    ;;

  hpke)
    rm -f \
      "${OUT_DIR}/pqc-rs-hpke-${VERSION}.crate" \
      "${OUT_DIR}/pqc-rs-hpke-package-list.txt"

    package_one pqc-rs-hpke
    ;;

  *)
    echo "Unknown stage: ${STAGE}" >&2
    usage
    exit 2
    ;;
esac

echo
echo "Stage '${STAGE}' artifacts written to ${OUT_DIR}/"
