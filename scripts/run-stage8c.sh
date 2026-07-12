#!/usr/bin/env bash
set -euo pipefail
./scripts/run-miri.sh
./scripts/run-address-sanitizer.sh
host="$(rustc -vV | sed -n 's/^host: //p')"
if [[ "${host}" == *-unknown-linux-gnu ]]; then
  ./scripts/run-undefined-behavior-sanitizer.sh
else
  echo "UBSan deferred to Linux CI"
fi
