#!/usr/bin/env bash
set -euo pipefail
OUT_DIR="${1:-vectors/nist-acvp/mldsa-keygen}"
REPOSITORY="https://github.com/usnistgov/ACVP-Server.git"
SUBDIR="gen-val/json-files/ML-DSA-keyGen-FIPS204"
mkdir -p "${OUT_DIR}"
COMMIT="$(git ls-remote "${REPOSITORY}" refs/heads/master | awk '{print $1}')"
[[ -n "${COMMIT}" ]] || { echo "Could not resolve ACVP-Server commit" >&2; exit 1; }
BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/${COMMIT}/${SUBDIR}"
for file in prompt.json expectedResults.json validation.json registration.json; do
  curl --fail --location --silent --show-error "${BASE}/${file}" --output "${OUT_DIR}/${file}"
done
cat > "${OUT_DIR}/SOURCE.txt" <<EOF
repository=${REPOSITORY}
commit=${COMMIT}
subdirectory=${SUBDIR}
fetched_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF
echo "Fetched NIST ACVP ML-DSA keyGen vectors at ${COMMIT}"
