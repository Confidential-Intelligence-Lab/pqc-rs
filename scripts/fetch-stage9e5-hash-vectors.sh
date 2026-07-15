#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-vectors/nist-acvp}"
REPOSITORY="https://github.com/usnistgov/ACVP-Server.git"
COMMIT="$(git ls-remote "${REPOSITORY}" refs/heads/master | awk '{print $1}')"

for MODE in sigGen sigVer; do
  case "${MODE}" in
    sigGen)
      MODE_DIR="siggen"
      ;;
    sigVer)
      MODE_DIR="sigver"
      ;;
    *)
      echo "Unsupported mode: ${MODE}" >&2
      exit 1
      ;;
  esac

  DIR="${ROOT}/mldsa-${MODE_DIR}"
  SUBDIR="gen-val/json-files/ML-DSA-${MODE}-FIPS204"
  mkdir -p "${DIR}"

  for FILE in prompt.json expectedResults.json registration.json validation.json internalProjection.json; do
    curl --fail --location --silent --show-error       "https://raw.githubusercontent.com/usnistgov/ACVP-Server/${COMMIT}/${SUBDIR}/${FILE}"       --output "${DIR}/${FILE}"
  done

  cat > "${DIR}/HASH_SOURCE.txt" <<EOF
repository=${REPOSITORY}
commit=${COMMIT}
subdirectory=${SUBDIR}
scope=external-preHash
EOF
done

echo "Fetched HashML-DSA vectors at ${COMMIT}"
