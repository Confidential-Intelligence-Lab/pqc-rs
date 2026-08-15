#!/bin/zsh
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE="paper/evaluation/raw/secure-channel"
SOURCE="$BASE/runs"
ARCHIVE="$BASE/accepted-runs"

ACCEPTED_RUNS=(
  "2026-08-15-m4-ac-run04"
  "2026-08-15-m4-ac-run06"
  "2026-08-15-m4-ac-run07"
  "2026-08-15-m4-ac-run08"
  "2026-08-15-m4-ac-run09"
)

echo "===== interpreter ====="
echo "/bin/zsh"
echo

echo "===== rebuilding accepted-run archive ====="
rm -rf "$ARCHIVE"
mkdir -p "$ARCHIVE"

for RUN_ID in "${ACCEPTED_RUNS[@]}"; do
  SRC="$SOURCE/$RUN_ID"
  DST="$ARCHIVE/$RUN_ID"

  echo "archiving $RUN_ID"

  if [[ ! -d "$SRC" ]]; then
    echo "ERROR: missing source run: $SRC" >&2
    exit 1
  fi

  if [[ ! -f "$SRC/RUN.txt" ]]; then
    echo "ERROR: missing RUN.txt for $RUN_ID" >&2
    exit 1
  fi

  if [[ ! -f "$SRC/criterion-output.txt" ]]; then
    echo "ERROR: missing criterion-output.txt for $RUN_ID" >&2
    exit 1
  fi

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

  if [[ "$JSON_COUNT" -ne 96 ]]; then
    echo "ERROR: $RUN_ID has $JSON_COUNT JSON artifacts; expected 96" >&2
    exit 1
  fi

  if [[ "$ESTIMATE_COUNT" -ne 24 ]]; then
    echo "ERROR: $RUN_ID has $ESTIMATE_COUNT estimate files; expected 24" >&2
    exit 1
  fi

  echo "  JSON artifacts: $JSON_COUNT"
  echo "  estimates:      $ESTIMATE_COUNT"
done

echo
echo "===== archive summary ====="
du -sh "$ARCHIVE"

echo
echo "ARCHIVE: PASS"
