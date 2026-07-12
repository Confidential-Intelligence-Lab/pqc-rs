#!/usr/bin/env bash
set -euo pipefail
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-disable-isolation}"
for package in pqc-core pqc-ml-kem pqc-hpke; do
  echo "== Miri: ${package} library tests =="
  cargo +nightly miri test -p "${package}" --lib --all-features
done
