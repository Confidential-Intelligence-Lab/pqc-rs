#!/usr/bin/env bash
set -euo pipefail
profile="${1:-portable}"
python3 scripts/stage12_campaign.py --profile "$profile" --output "target/stage12/$profile"
