#!/usr/bin/env bash
set -euo pipefail
host="$(rustc -vV | sed -n 's/^host: //p')"
case "${host}" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;;
  *) echo "UBSan is run in Linux CI only; current host is ${host}" >&2; exit 2 ;;
esac
export RUSTFLAGS="-Zsanitizer=undefined -Cforce-frame-pointers=yes"
export RUSTDOCFLAGS="-Zsanitizer=undefined -Cforce-frame-pointers=yes"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-halt_on_error=1:print_stacktrace=1}"
cargo +nightly test --workspace --all-features --target "${host}"
