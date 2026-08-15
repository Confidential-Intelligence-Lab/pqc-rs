#!/bin/zsh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE="paper/evaluation/raw/secure-channel"
FREEZE="$BASE/freeze"

PYTHON_BIN="$(command -v python3)"

if [[ -z "$PYTHON_BIN" ]]; then
  echo "ERROR: python3 not found" >&2
  exit 1
fi

echo "===== interpreters ====="
echo "shell=/bin/zsh"
echo "python=$PYTHON_BIN"
"$PYTHON_BIN" --version
echo

echo "===== archive accepted runs ====="
/bin/zsh paper/evaluation/scripts/archive_secure_channel_e2.zsh

echo
echo "===== freeze verification ====="
/bin/sh "$FREEZE/verify_accepted_runs.sh"

echo
echo "===== preserve current generated CSVs ====="
cp "$FREEZE/accepted_estimates.csv" /tmp/accepted_estimates.before
cp "$FREEZE/cross_run_summary.csv" /tmp/cross_run_summary.before

echo
echo "===== regenerate ====="
"$PYTHON_BIN" "$FREEZE/extract_accepted_estimates.py"

echo
echo "===== deterministic comparison ====="
cmp \
  /tmp/accepted_estimates.before \
  "$FREEZE/accepted_estimates.csv"

cmp \
  /tmp/cross_run_summary.before \
  "$FREEZE/cross_run_summary.csv"

echo
echo "===== row counts ====="
ACCEPTED_LINES="$(wc -l < "$FREEZE/accepted_estimates.csv" | tr -d ' ')"
SUMMARY_LINES="$(wc -l < "$FREEZE/cross_run_summary.csv" | tr -d ' ')"

echo "accepted_estimates_lines=$ACCEPTED_LINES"
echo "cross_run_summary_lines=$SUMMARY_LINES"

if [[ "$ACCEPTED_LINES" -ne 121 ]]; then
  echo "ERROR: expected 121 accepted-estimate CSV lines" >&2
  exit 1
fi

if [[ "$SUMMARY_LINES" -ne 25 ]]; then
  echo "ERROR: expected 25 summary CSV lines" >&2
  exit 1
fi

echo
echo "===== Git hygiene ====="
git diff --check

echo
echo "E2 REPRODUCIBILITY: PASS"
