#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-vectors/nist-acvp/mldsa-sigver}"
REPOSITORY="https://github.com/usnistgov/ACVP-Server.git"
SUBDIR="gen-val/json-files/ML-DSA-sigVer-FIPS204"

mkdir -p "${OUT_DIR}"

COMMIT="$(git ls-remote "${REPOSITORY}" refs/heads/master | awk '{print $1}')"
if [[ -z "${COMMIT}" ]]; then
  echo "Could not resolve ACVP-Server master commit" >&2
  exit 1
fi

BASE_URL="https://raw.githubusercontent.com/usnistgov/ACVP-Server/${COMMIT}/${SUBDIR}"

for file in prompt.json expectedResults.json validation.json registration.json internalProjection.json; do
  curl --fail --location --silent --show-error \
    "${BASE_URL}/${file}" \
    --output "${OUT_DIR}/${file}"
done

cat > "${OUT_DIR}/SOURCE.txt" <<EOF
repository=${REPOSITORY}
commit=${COMMIT}
subdirectory=${SUBDIR}
scope=external-pure
fetched_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo "Fetched NIST ACVP ML-DSA sigVer vectors at ${COMMIT}"
