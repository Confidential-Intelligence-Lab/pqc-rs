#!/usr/bin/env bash
set -euo pipefail

readonly URL="https://raw.githubusercontent.com/hpkewg/hpke-pq/main/test-vectors.json"
readonly OUT_DIR="tests/vectors/hpke-pq"
readonly OUT="${OUT_DIR}/draft-ietf-hpke-pq-05-test-vectors.json"

mkdir -p "${OUT_DIR}"

curl       --fail       --location       --retry 5       --retry-all-errors       --connect-timeout 20       "${URL}"       --output "${OUT}.tmp"

python3 - "${OUT}.tmp" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    vectors = json.load(handle)

if not isinstance(vectors, list):
    raise SystemExit("vector file must contain a JSON array")

suites = {
    (entry.get("mode"), entry.get("kem_id"), entry.get("kdf_id"), entry.get("aead_id"))
    for entry in vectors
}

required = {
    (0, 0x0040, 0x0001, 0x0001),
    (0, 0x0041, 0x0001, 0x0001),
    (0, 0x0042, 0x0002, 0x0002),
}

missing = required - suites
if missing:
    raise SystemExit(f"missing required pure ML-KEM suites: {sorted(missing)}")

print(f"validated {len(vectors)} HPKE-PQ vector suites")
PY

mv "${OUT}.tmp" "${OUT}"

python3 - "${OUT}" "${OUT_DIR}/SHA256SUMS" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
output = pathlib.Path(sys.argv[2])
digest = hashlib.sha256(path.read_bytes()).hexdigest()
output.write_text(f"{digest}  {path.name}\n", encoding="utf-8")
PY

cat > "${OUT_DIR}/PROVENANCE.txt" <<'EOF'
Document: draft-ietf-hpke-pq-05
Vector repository: https://github.com/hpkewg/hpke-pq
Vector path: test-vectors.json
Retrieval policy: fetched explicitly by scripts/fetch-hpke-pq-vectors.sh
Conformance scope: pure ML-KEM Base-mode suites only
EOF

echo "Wrote ${OUT}"
