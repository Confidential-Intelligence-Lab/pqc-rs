#!/usr/bin/env bash
set -uo pipefail
python3 scripts/stage11_sidechannel.py --experiments sidechannel/experiments --output target/stage11a
status=$?
case "$status" in
  0) echo "Stage 11A evidence collection passed." ;;
  2) echo "Stage 11A evidence collection is inconclusive; inspect target/stage11a/report.md." ;;
  *) echo "Stage 11A evidence collection failed." >&2; exit "$status" ;;
esac
