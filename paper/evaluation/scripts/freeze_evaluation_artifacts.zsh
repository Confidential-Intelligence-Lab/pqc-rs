#!/bin/zsh

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

EXPECTED_REVISION="218f3a3165cc5355ce084b63ac69082cac1afa26"
MANIFEST="paper/evaluation/FINAL_EVALUATION_FREEZE.txt"

ARTIFACTS=(
  "paper/evaluation/raw/secure-channel/freeze/cross_run_summary.csv"
  "paper/evaluation/raw/hpke-composition/freeze/composition_summary.csv"
  "paper/evaluation/raw/secure-channel/e4/negative_matrix-results.psv"
  "paper/evaluation/raw/secure-channel/e5/loopback_tcp-results.psv"
  "paper/evaluation/raw/secure-channel/e6/adverse_schedule-results.psv"
  "paper/evaluation/scripts/reproduce_secure_channel_demo.zsh"
  "paper/evaluation/derived/secure-channel-summary.csv"
  "paper/evaluation/derived/hpke-composition-summary.csv"
  "paper/evaluation/derived/secure-channel-summary.tex"
  "paper/evaluation/derived/hpke-composition-summary.tex"
  "paper/evaluation/derived/figures/hpke-composition-overhead.pdf"
  "paper/evaluation/raw/secure-channel/e9/change-localization-results.psv"
  "paper/evaluation/raw/secure-channel/e9/change-localization-summary.txt"
)

fail() {
  echo "FINAL EVALUATION FREEZE: FAIL - $*" >&2
  exit 1
}

revision="$(git rev-parse HEAD)"

[[ "$revision" == "$EXPECTED_REVISION" ]] \
  || fail "unexpected baseline revision: $revision"

for artifact in "${ARTIFACTS[@]}"; do
  [[ -f "$artifact" ]] \
    || fail "missing canonical artifact: $artifact"
done

tmp_manifest="$(mktemp)"
trap 'rm -f "$tmp_manifest"' EXIT

{
  echo "PQC-Forge Final Evaluation Freeze"
  echo
  echo "Evaluated revision:"
  echo "$EXPECTED_REVISION"
  echo
  echo "Canonical artifacts:"
  echo

  for artifact in "${ARTIFACTS[@]}"; do
    digest="$(shasum -a 256 "$artifact" | awk '{print $1}')"
    printf "%s  %s\n" "$digest" "$artifact"
  done

  echo
  echo "Verification:"
  echo "FINAL BASELINE REVISION: PASS"
  echo "CANONICAL ARTIFACT INVENTORY: PASS"
  echo "CANONICAL ARTIFACT HASHING: PASS"
  echo
  echo "FINAL EVALUATION FREEZE: PASS"
} > "$tmp_manifest"

mv "$tmp_manifest" "$MANIFEST"
trap - EXIT

echo "FINAL BASELINE REVISION: PASS"
echo "CANONICAL ARTIFACT INVENTORY: PASS"
echo "CANONICAL ARTIFACT HASHING: PASS"
echo
echo "FINAL EVALUATION FREEZE: PASS"
