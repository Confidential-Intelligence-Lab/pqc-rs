#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

SRC="$ROOT/scripts/interop/bench/BouncyCastleBench.java"
CLASSES="$ROOT/target/provider-bench/bouncycastle-classes"
OUT="$ROOT/target/camera-ready-provider-bench/bouncycastle"
RAW="$OUT/all-results.txt"

BC_JAR="${BC_JAVA_JAR:-/tmp/pqc-rs-bc-audit/bc-java/prov/build/libs/bcprov-jdk18on-1.87-SNAPSHOT.jar}"

if [[ ! -f "$BC_JAR" ]]; then
    echo "Bouncy Castle JAR not found: $BC_JAR" >&2
    exit 1
fi

mkdir -p "$CLASSES" "$OUT"
rm -rf "$CLASSES"/*

javac \
    -cp "$BC_JAR" \
    -d "$CLASSES" \
    "$SRC"

echo "Java:"
java -version 2>&1 | head -3

echo "Bouncy Castle JAR:"
echo "$BC_JAR"

echo "Bouncy Castle JAR SHA-256:"
shasum -a 256 "$BC_JAR"

java \
    -cp "$BC_JAR:$CLASSES" \
    BouncyCastleBench \
    > "$RAW"

python3 - "$RAW" "$OUT" <<'PY'
import pathlib
import sys

raw = pathlib.Path(sys.argv[1]).read_text()
out = pathlib.Path(sys.argv[2])

ops = (
    "kem-keygen",
    "kem-encaps",
    "kem-decaps",
    "dsa-keygen",
    "dsa-sign",
    "dsa-verify",
)

for op in ops:
    begin = f"===BEGIN:{op}===\n"
    end = f"\n===END:{op}==="

    if begin not in raw or end not in raw:
        raise SystemExit(
            f"missing benchmark delimiters for {op}"
        )

    payload = raw.split(begin, 1)[1].split(end, 1)[0]
    path = out / f"{op}.json"
    path.write_text(payload.strip() + "\n")
    print(f"wrote {path}")
PY
