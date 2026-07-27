#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [repository]" >&2
  exit 64
fi

readonly script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
readonly repo="${1:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
readonly manifest="${repo}/crates/pqc-ml-dsa/Cargo.toml"
readonly lib_rs="${repo}/crates/pqc-ml-dsa/src/lib.rs"

for tool in cargo python3 rg; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "required tool is missing: ${tool}" >&2
    exit 1
  }
done

python3 - "${lib_rs}" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
lines = text.splitlines()
always_public = set()
for index, line in enumerate(lines):
    match = re.fullmatch(r"pub mod ([A-Za-z0-9_]+);", line)
    if match and (index == 0 or lines[index - 1] != "#[doc(hidden)]"):
        always_public.add(match.group(1))
expected = {"api", "error", "params"}
if always_public != expected:
    raise SystemExit(
        "unexpected always-public ML-DSA modules: "
        f"expected={sorted(expected)!r} actual={sorted(always_public)!r}"
    )

internal = {
    "audit",
    "challenge",
    "constants",
    "encoding",
    "expand_a",
    "hash_mldsa",
    "hint",
    "keygen",
    "ntt",
    "poly",
    "reduce",
    "rounding",
    "sample",
    "signature",
    "signing",
    "signing_core",
    "verification",
    "xof",
}
for module in sorted(internal):
    public_pattern = (
        r'#\[cfg\(feature = "internal-api"\)\]\s*'
        r'#\[doc\(hidden\)\]\s*'
        rf'pub mod {module};'
    )
    private_pattern = (
        r'#\[cfg\(not\(feature = "internal-api"\)\)\]\s*'
        rf'mod {module};'
    )
    if not re.search(public_pattern, text):
        raise SystemExit(f"{module} lacks guarded hidden internal exposure")
    if not re.search(private_pattern, text):
        raise SystemExit(f"{module} lacks ordinary-build privacy")
PY

metadata="$(mktemp "${TMPDIR:-/tmp}/pqc-mldsa-boundary-metadata.XXXXXX")"
consumer="$(mktemp -d "${TMPDIR:-/tmp}/pqc-mldsa-boundary-consumer.XXXXXX")"
trap 'rm -f -- "${metadata}"; rm -rf -- "${consumer}"' EXIT

cargo metadata \
  --manifest-path "${repo}/Cargo.toml" \
  --locked \
  --no-deps \
  --format-version 1 >"${metadata}"

python3 - "${metadata}" <<'PY'
import json
import sys

metadata = json.load(open(sys.argv[1], encoding="utf-8"))
matches = [
    package for package in metadata["packages"]
    if package["name"] == "pqc-rs-ml-dsa"
]
if len(matches) != 1:
    raise SystemExit("expected exactly one pqc-rs-ml-dsa package")
features = matches[0]["features"]
if "internal-api" not in features:
    raise SystemExit("internal-api feature is absent")
if features["internal-api"]:
    raise SystemExit("internal-api feature must not activate dependencies")
if "internal-api" in features.get("default", []):
    raise SystemExit("internal-api must not be enabled by default")
PY

mkdir -p "${consumer}/src"
cat >"${consumer}/Cargo.toml" <<TOML
[package]
name = "pqc-rs-ml-dsa-public-boundary-check"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
pqc-rs-ml-dsa = { path = "${repo}/crates/pqc-ml-dsa" }
TOML

cat >"${consumer}/src/lib.rs" <<'RS'
use pqc_ml_dsa::{
    MlDsa, MlDsaError, MlDsaKeyGenSeed, MlDsaKeyPair, MlDsaParameterSet,
    MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature,
    PreHashAlgorithm, ML_DSA_KEYGEN_SEED_BYTES,
};

pub fn supported_surface() {
    let _ = core::mem::size_of::<MlDsa>();
    let _ = core::mem::size_of::<MlDsaError>();
    let _ = core::mem::size_of::<MlDsaKeyGenSeed>();
    let _ = core::mem::size_of::<MlDsaKeyPair>();
    let _ = core::mem::size_of::<MlDsaParameterSet>();
    let _ = core::mem::size_of::<MlDsaParameters>();
    let _ = core::mem::size_of::<MlDsaPrivateKey>();
    let _ = core::mem::size_of::<MlDsaPublicKey>();
    let _ = core::mem::size_of::<MlDsaSignature>();
    let _ = core::mem::size_of::<PreHashAlgorithm>();
    let _ = ML_DSA_KEYGEN_SEED_BYTES;
}
RS

cargo check \
  --manifest-path "${consumer}/Cargo.toml" \
  --quiet

cat >"${consumer}/src/lib.rs" <<'RS'
use pqc_ml_dsa::ntt;

pub fn unsupported_surface() {}
RS

if cargo check \
  --manifest-path "${consumer}/Cargo.toml" \
  --quiet >"${consumer}/negative.log" 2>&1; then
  echo "ordinary downstream build unexpectedly imported pqc_ml_dsa::ntt" >&2
  exit 1
fi

if ! rg -q 'private|unresolved import|could not find' "${consumer}/negative.log"; then
  echo "negative boundary check failed for an unexpected reason" >&2
  cat "${consumer}/negative.log" >&2
  exit 1
fi

cargo check \
  --manifest-path "${manifest}" \
  --features internal-api \
  --quiet

echo "ML-DSA public implementation boundary: pass"
