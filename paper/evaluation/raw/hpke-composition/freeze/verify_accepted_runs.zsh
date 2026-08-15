#!/bin/zsh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE="paper/evaluation/raw/hpke-composition"
RUNS="$BASE/accepted-runs"
EXPECTED_REVISION="db2af161a05796c0f046670330ec71c5d8b68741"

FAIL=0
COUNT=0

while IFS= read -r RUN_ID; do
  [[ -n "$RUN_ID" ]] || continue

  COUNT=$((COUNT + 1))
  DIR="$RUNS/$RUN_ID"

  echo "===== $RUN_ID ====="

  if [[ ! -d "$DIR" ]]; then
    echo "FAIL: missing run directory"
    FAIL=1
    continue
  fi

  REVISION="$(sed -n 's/^revision=//p' "$DIR/RUN.txt" | head -n 1)"
  EXIT_STATUS="$(sed -n 's/^benchmark_exit_status=//p' "$DIR/RUN.txt" | head -n 1)"
  STATUS="$(sed -n 's/^status=//p' "$DIR/RUN.txt" | tail -n 1)"

  ANALYSES="$(
    grep -c '^Benchmarking hpke/composition/.*/.*: Analyzing' \
      "$DIR/criterion-output.txt" || true
  )"

  ESTIMATES="$(
    find "$DIR/criterion" \
      -path '*/new/estimates.json' \
      -type f | wc -l | tr -d ' '
  )"

  AC_OBS="$(
    grep -c "Now drawing from 'AC Power'" "$DIR/RUN.txt" || true
  )"

  BATTERY_OBS="$(
    grep -c "Now drawing from 'Battery Power'" "$DIR/RUN.txt" || true
  )"

  printf 'revision=%s\n' "$REVISION"
  printf 'exit_status=%s\n' "$EXIT_STATUS"
  printf 'status=%s\n' "$STATUS"
  printf 'analyses=%s\n' "$ANALYSES"
  printf 'new_estimates=%s\n' "$ESTIMATES"
  printf 'ac_observations=%s\n' "$AC_OBS"
  printf 'battery_observations=%s\n' "$BATTERY_OBS"

  [[ "$REVISION" == "$EXPECTED_REVISION" ]] || {
    echo "FAIL: revision mismatch"
    FAIL=1
  }

  [[ "$EXIT_STATUS" == "0" ]] || {
    echo "FAIL: benchmark exit status"
    FAIL=1
  }

  [[ "$STATUS" == "accepted" ]] || {
    echo "FAIL: status is not accepted"
    FAIL=1
  }

  [[ "$ANALYSES" -eq 8 ]] || {
    echo "FAIL: expected 8 analyzed cases"
    FAIL=1
  }

  [[ "$ESTIMATES" -eq 8 ]] || {
    echo "FAIL: expected 8 estimate files"
    FAIL=1
  }

  [[ "$AC_OBS" -eq 2 ]] || {
    echo "FAIL: expected exactly 2 AC observations"
    FAIL=1
  }

  [[ "$BATTERY_OBS" -eq 0 ]] || {
    echo "FAIL: battery observation present"
    FAIL=1
  }

  echo
done < "$BASE/freeze/ACCEPTED_RUNS.txt"

[[ "$COUNT" -eq 5 ]] || {
  echo "FAIL: expected 5 accepted runs, found $COUNT"
  FAIL=1
}

if [[ "$FAIL" -ne 0 ]]; then
  echo "E3 DATASET FREEZE VERIFICATION: FAIL"
  exit 1
fi

echo "E3 DATASET FREEZE VERIFICATION: PASS"
echo "accepted_runs=5"
echo "cases_per_run=8"
echo "accepted_distributions=40"
echo "revision=$EXPECTED_REVISION"
