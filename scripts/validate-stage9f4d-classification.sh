#!/usr/bin/env bash
set -euo pipefail
CSV="${1:-audit/stage9f4d/instruction-classification.csv}"
python3 scripts/stage9f4d-classify.py validate "${CSV}"
