#!/usr/bin/env bash
set -euo pipefail

mkdir -p target/release-candidate
rm -f target/release-candidate/*.crate

cargo package -p pqc-core --list > target/release-candidate/pqc-core-package-list.txt
cargo package -p pqc-core

for crate in pqc-ml-kem pqc-hpke; do
  cargo package -p "${crate}" --list > "target/release-candidate/${crate}-package-list.txt"
  cargo package -p "${crate}" --no-verify
done

cp target/package/*.crate target/release-candidate/

{
  date -u
  rustc -Vv
  cargo -V
  git rev-parse HEAD
  git status --short
} > target/release-candidate/build-record.txt

echo "Release candidate artifacts written to target/release-candidate/"
