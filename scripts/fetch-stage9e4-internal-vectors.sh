#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${1:-vectors/nist-acvp}"
REPOSITORY="https://github.com/usnistgov/ACVP-Server.git"
COMMIT="$(git ls-remote "${REPOSITORY}" refs/heads/master | awk '{print $1}')"
for MODE in sigGen sigVer; do
  DIR="${OUT_DIR}/mldsa-${MODE,,}"
  SUBDIR="gen-val/json-files/ML-DSA-${MODE}-FIPS204"
  BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/${COMMIT}/${SUBDIR}"
  mkdir -p "${DIR}"
  for FILE in prompt.json expectedResults.json internalProjection.json registration.json validation.json; do
    curl --fail --location --silent --show-error "${BASE}/${FILE}" --output "${DIR}/${FILE}"
  done
  printf 'repository=%s\ncommit=%s\nsubdirectory=%s\nscope=internal\n' "${REPOSITORY}" "${COMMIT}" "${SUBDIR}" > "${DIR}/SOURCE.txt"
done
echo "Fetched NIST ACVP ML-DSA internal vectors at ${COMMIT}"
