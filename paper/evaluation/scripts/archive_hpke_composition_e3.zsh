#!/bin/zsh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE="paper/evaluation/raw/hpke-composition"
SOURCE="$BASE/runs"
ARCHIVE="$BASE/accepted-runs"

ACCEPTED_RUNS=(
  "2026-08-15-m4-e3-run02"
  "2026-08-15-m4-e3-run03"
  "2026-08-15-m4-e3-run04"
  "2026-08-15-m4-e3-run05"
  "2026-08-15-m4-e3-run06"
)

rm -rf "$ARCHIVE"
mkdir -p "$ARCHIVE"

for RUN_ID in "${ACCEPTED_RUNS[@]}"; do
  SRC="$SOURCE/$RUN_ID"
  DST="$ARCHIVE/$RUN_ID"

  [[ -d "$SRC" ]] || {
    echo "ERROR: missing $SRC" >&2
    exit 1
  }

  mkdir -p "$DST"

  cp "$SRC/RUN.txt" "$DST/RUN.txt"
  cp "$SRC/criterion-output.txt" "$DST/criterion-output.txt"

  while IFS= read -r FILE; do
    REL="${FILE#$SRC/}"
    mkdir -p "$DST/${REL:h}"
    cp "$FILE" "$DST/$REL"
  done < <(
    find "$SRC/criterion" \
      -path '*/new/*.json' \
      -type f \
      -print | sort
  )

  JSON_COUNT=$(
    find "$DST/criterion" \
      -path '*/new/*.json' \
      -type f | wc -l | tr -d ' '
  )

  ESTIMATE_COUNT=$(
    find "$DST/criterion" \
      -path '*/new/estimates.json' \
      -type f | wc -l | tr -d ' '
  )

  [[ "$JSON_COUNT" -eq 32 ]] || {
    echo "ERROR: $RUN_ID has $JSON_COUNT JSON files; expected 32" >&2
    exit 1
  }

  [[ "$ESTIMATE_COUNT" -eq 8 ]] || {
    echo "ERROR: $RUN_ID has $ESTIMATE_COUNT estimates; expected 8" >&2
    exit 1
  }

  echo "$RUN_ID: JSON=$JSON_COUNT estimates=$ESTIMATE_COUNT"
done

echo
du -sh "$ARCHIVE"
echo "E3 ARCHIVE: PASS"
