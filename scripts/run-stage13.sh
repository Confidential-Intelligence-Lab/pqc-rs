#!/usr/bin/env bash
set -euo pipefail
profile="${1:-portable}"
python3 scripts/stage13_assurance.py --profile "$profile" --output "target/stage13/$profile"
