\
#!/usr/bin/env bash
set -euo pipefail

OWNER="usnistgov"
REPOSITORY="ACVP-Server"
BRANCH="${ACVP_BRANCH:-master}"
DESTINATION="${1:-tests/kat/acvp/upstream}"

API_BASE="https://api.github.com/repos/${OWNER}/${REPOSITORY}"
RAW_BASE="https://raw.githubusercontent.com/${OWNER}/${REPOSITORY}"

CURL_COMMON=(
    --fail
    --location
    --silent
    --show-error
    --retry 8
    --retry-all-errors
    --retry-delay 2
    --connect-timeout 20
    --max-time 300
)

if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    CURL_COMMON+=(
        --header "Authorization: Bearer ${GITHUB_TOKEN}"
        --header "X-GitHub-Api-Version: 2022-11-28"
    )
fi

resolve_revision() {
    local response
    response="$(curl "${CURL_COMMON[@]}" \
        "${API_BASE}/commits/${BRANCH}")"

    python3 -c '
import json
import sys

document = json.load(sys.stdin)
sha = document.get("sha")
if not isinstance(sha, str) or len(sha) != 40:
    raise SystemExit("GitHub API response did not contain a 40-character commit SHA")
print(sha)
' <<< "${response}"
}

download_file() {
    local relative_path="$1"
    local target_path="${DESTINATION}/${relative_path}"
    local temporary_path="${target_path}.part"
    local url="${RAW_BASE}/${REVISION}/${relative_path}"

    mkdir -p "$(dirname "${target_path}")"

    printf 'Downloading %s\n' "${relative_path}"
    curl "${CURL_COMMON[@]}" \
        --output "${temporary_path}" \
        "${url}"

    if [[ ! -s "${temporary_path}" ]]; then
        printf 'Downloaded file is empty: %s\n' "${relative_path}" >&2
        rm -f "${temporary_path}"
        return 1
    fi

    python3 -m json.tool "${temporary_path}" >/dev/null
    mv "${temporary_path}" "${target_path}"
}

printf 'Resolving %s/%s branch %s...\n' \
    "${OWNER}" "${REPOSITORY}" "${BRANCH}"
REVISION="$(resolve_revision)"
printf 'Resolved immutable commit: %s\n' "${REVISION}"

FILES=(
    "gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json"
    "gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json"
    "gen-val/json-files/ML-KEM-encapDecap-FIPS203/prompt.json"
    "gen-val/json-files/ML-KEM-encapDecap-FIPS203/expectedResults.json"
)

mkdir -p "${DESTINATION}"

for relative_path in "${FILES[@]}"; do
    download_file "${relative_path}"
done

cat > "${DESTINATION}/PROVENANCE.txt" <<EOF
repository=https://github.com/${OWNER}/${REPOSITORY}.git
branch=${BRANCH}
commit=${REVISION}
fetched_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
transport=raw-files-with-retries
status=authoritative-source-imported-not-yet-passed
EOF

(
    cd "${DESTINATION}"
    if command -v shasum >/dev/null 2>&1; then
        find gen-val -type f -name '*.json' -print0 |
            sort -z |
            xargs -0 shasum -a 256 > SHA256SUMS
    elif command -v sha256sum >/dev/null 2>&1; then
        find gen-val -type f -name '*.json' -print0 |
            sort -z |
            xargs -0 sha256sum > SHA256SUMS
    else
        printf 'No SHA-256 utility found; checksums were not generated.\n' >&2
    fi
)

printf 'Fetched NIST ACVP ML-KEM vectors into %s\n' "${DESTINATION}"
printf 'Pinned commit: %s\n' "${REVISION}"
