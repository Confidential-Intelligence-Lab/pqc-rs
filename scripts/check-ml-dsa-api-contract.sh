#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: $0 [repository]" >&2
  exit 64
fi

readonly script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
readonly repo="${1:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
readonly src="${repo}/crates/pqc-ml-dsa/src"

for tool in cargo python3 rg; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "required tool is missing: ${tool}" >&2
    exit 1
  }
done

python3 - "${src}" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
lib = (src / "lib.rs").read_text(encoding="utf-8")
api = (src / "api.rs").read_text(encoding="utf-8")
error = (src / "error.rs").read_text(encoding="utf-8")
params = (src / "params.rs").read_text(encoding="utf-8")
hash_mldsa = (src / "hash_mldsa.rs").read_text(encoding="utf-8")

def fail(label, expected, actual):
    raise SystemExit(
        f"{label} changed: expected={sorted(expected)!r} actual={sorted(actual)!r}"
    )

always_public = set()
lines = lib.splitlines()
for index, line in enumerate(lines):
    match = re.fullmatch(r"pub mod ([A-Za-z0-9_]+);", line)
    if match and (index == 0 or lines[index - 1] != "#[doc(hidden)]"):
        always_public.add(match.group(1))
expected_modules = {"api", "error", "params"}
if always_public != expected_modules:
    fail("public modules", expected_modules, always_public)

root_exports = set()
for match in re.finditer(r"pub use\s+([^;]+);", lib, re.S):
    statement = match.group(1)
    if "{" in statement:
        names = statement.split("{", 1)[1].rsplit("}", 1)[0]
        root_exports.update(
            name.strip().split(" as ")[-1]
            for name in names.split(",")
            if name.strip()
        )
    else:
        root_exports.add(statement.rsplit("::", 1)[-1].strip())
expected_exports = {
    "MlDsa",
    "MlDsaError",
    "MlDsaKeyGenSeed",
    "MlDsaKeyPair",
    "MlDsaParameterSet",
    "MlDsaParameters",
    "MlDsaPrivateKey",
    "MlDsaPublicKey",
    "MlDsaSignature",
    "PreHashAlgorithm",
    "ML_DSA_KEYGEN_SEED_BYTES",
}
if root_exports != expected_exports:
    fail("crate-root exports", expected_exports, root_exports)

def impl_body(text, type_name):
    match = re.search(rf"\bimpl {type_name}\s*\{{", text)
    if not match:
        raise SystemExit(f"missing impl for {type_name}")
    start = match.end()
    depth = 1
    index = start
    while depth and index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    if depth:
        raise SystemExit(f"unterminated impl for {type_name}")
    return text[start:index - 1]

def public_methods(text, type_name):
    body = impl_body(text, type_name)
    return set(re.findall(r"\bpub\s+(?:const\s+)?fn\s+([A-Za-z0-9_]+)", body))

expected_methods = {
    "MlDsaKeyGenSeed": {"from_bytes", "parameter_set", "as_bytes", "expand"},
    "MlDsaPublicKey": {"from_bytes", "parameter_set", "as_bytes", "into_bytes"},
    "MlDsaPrivateKey": {"from_bytes", "parameter_set", "as_bytes"},
    "MlDsaSignature": {"from_bytes", "parameter_set", "as_bytes", "into_bytes"},
    "MlDsaKeyPair": {"public_key", "private_key", "into_parts"},
    "MlDsa": {
        "new",
        "parameter_set",
        "public_key_bytes",
        "private_key_bytes",
        "signature_bytes",
        "keygen",
        "generate_keygen_seed",
        "keygen_from_seed",
        "sign_deterministic",
        "sign_hedged",
        "verify",
        "hash_sign_deterministic",
        "hash_sign_hedged",
        "hash_verify",
    },
}
for type_name, expected in expected_methods.items():
    actual = public_methods(api, type_name)
    if actual != expected:
        fail(f"{type_name} methods", expected, actual)

parameter_methods = public_methods(params, "MlDsaParameterSet")
if parameter_methods != {"parameters", "name"}:
    fail(
        "MlDsaParameterSet methods",
        {"parameters", "name"},
        parameter_methods,
    )

def enum_variants(text, enum_name):
    match = re.search(rf"\bpub enum {enum_name}\s*\{{(.*?)^\}}", text, re.S | re.M)
    if not match:
        raise SystemExit(f"missing public enum {enum_name}")
    return set(
        re.findall(
            r"^\s{4}([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\{|\()",
            match.group(1),
            re.M,
        )
    )

expected_variants = {
    "MlDsaParameterSet": {"MlDsa44", "MlDsa65", "MlDsa87"},
    "MlDsaError": {
        "InvalidPublicKey",
        "InvalidPrivateKey",
        "InvalidSignature",
        "ContextTooLong",
        "ParameterSetMismatch",
        "RandomnessFailure",
        "RejectionLimitExceeded",
        "InternalError",
    },
    "PreHashAlgorithm": {
        "Sha2_224",
        "Sha2_256",
        "Sha2_384",
        "Sha2_512",
        "Sha2_512_224",
        "Sha2_512_256",
        "Sha3_224",
        "Sha3_256",
        "Sha3_384",
        "Sha3_512",
        "Shake128",
        "Shake256",
    },
}
for text, enum_name in (
    (params, "MlDsaParameterSet"),
    (error, "MlDsaError"),
    (hash_mldsa, "PreHashAlgorithm"),
):
    actual = enum_variants(text, enum_name)
    expected = expected_variants[enum_name]
    if actual != expected:
        fail(f"{enum_name} variants", expected, actual)

parameters_match = re.search(
    r"\bpub struct MlDsaParameters\s*\{(.*?)^\}",
    params,
    re.S | re.M,
)
if not parameters_match:
    raise SystemExit("missing MlDsaParameters")
parameter_fields = set(
    re.findall(
        r"^\s{4}pub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:",
        parameters_match.group(1),
        re.M,
    )
)
expected_fields = {
    "k",
    "l",
    "eta",
    "tau",
    "gamma1",
    "gamma2",
    "omega",
    "public_key_bytes",
    "private_key_bytes",
    "signature_bytes",
}
if parameter_fields != expected_fields:
    fail("MlDsaParameters fields", expected_fields, parameter_fields)

if not re.search(
    r'#\[cfg\(feature = "internal-api"\)\]\s*'
    r'pub fn from_acvp_name',
    hash_mldsa,
):
    raise SystemExit("ACVP prehash parser is not restricted to internal-api")
PY

consumer="$(mktemp -d "${TMPDIR:-/tmp}/pqc-mldsa-api-contract.XXXXXX")"
trap 'rm -rf -- "${consumer}"' EXIT
mkdir -p "${consumer}/src"

cat >"${consumer}/Cargo.toml" <<TOML
[package]
name = "pqc-rs-ml-dsa-api-contract-check"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
pqc-rs-ml-dsa = { path = "${repo}/crates/pqc-ml-dsa" }
rand_core = "0.6"
TOML

cat >"${consumer}/src/lib.rs" <<'RS'
#![deny(warnings)]

use pqc_ml_dsa::{
    MlDsa, MlDsaError, MlDsaKeyGenSeed, MlDsaKeyPair, MlDsaParameterSet,
    MlDsaParameters, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature,
    PreHashAlgorithm, ML_DSA_KEYGEN_SEED_BYTES,
};
use rand_core::{CryptoRng, RngCore};

fn clone_debug_eq<T: Clone + core::fmt::Debug + Eq + PartialEq>() {}
fn copy_contract<T: Clone + Copy + core::fmt::Debug + Eq + PartialEq>() {}
fn error_contract<T: std::error::Error + Clone + Copy + Eq + PartialEq>() {}

pub fn traits() {
    copy_contract::<MlDsa>();
    copy_contract::<MlDsaParameterSet>();
    copy_contract::<MlDsaParameters>();
    copy_contract::<MlDsaError>();
    copy_contract::<PreHashAlgorithm>();
    error_contract::<MlDsaError>();
    clone_debug_eq::<MlDsaPublicKey>();
    clone_debug_eq::<MlDsaSignature>();
}

pub fn signatures<R: CryptoRng + RngCore>(
    rng: &mut R,
    encoded: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<(), MlDsaError> {
    let parameter_set = MlDsaParameterSet::MlDsa44;
    let implementation: MlDsa = MlDsa::new(parameter_set);
    let _: MlDsaParameterSet = implementation.parameter_set();
    let _: usize = implementation.public_key_bytes();
    let _: usize = implementation.private_key_bytes();
    let _: usize = implementation.signature_bytes();
    let _: &'static str = parameter_set.name();
    let parameters: MlDsaParameters = parameter_set.parameters();
    let _: usize = parameters.k;
    let _: usize = parameters.l;
    let _: i32 = parameters.eta;
    let _: usize = parameters.tau;
    let _: i32 = parameters.gamma1;
    let _: i32 = parameters.gamma2;
    let _: usize = parameters.omega;
    let _: usize = parameters.public_key_bytes;
    let _: usize = parameters.private_key_bytes;
    let _: usize = parameters.signature_bytes;

    let seed: MlDsaKeyGenSeed =
        MlDsaKeyGenSeed::from_bytes(parameter_set, [0_u8; ML_DSA_KEYGEN_SEED_BYTES]);
    let _: MlDsaParameterSet = seed.parameter_set();
    let _: &[u8; ML_DSA_KEYGEN_SEED_BYTES] = seed.as_bytes();
    let _: MlDsaKeyPair = seed.expand()?;
    let _: MlDsaKeyPair = implementation.generate_keygen_seed(rng)?.expand()?;
    let key_pair: MlDsaKeyPair = implementation.keygen(rng)?;
    let _: &MlDsaPublicKey = key_pair.public_key();
    let _: &MlDsaPrivateKey = key_pair.private_key();

    let public_key = MlDsaPublicKey::from_bytes(parameter_set, encoded)?;
    let _: MlDsaParameterSet = public_key.parameter_set();
    let _: &[u8] = public_key.as_bytes();
    let _: Vec<u8> = public_key.clone().into_bytes();

    let private_key = MlDsaPrivateKey::from_bytes(parameter_set, encoded)?;
    let _: MlDsaParameterSet = private_key.parameter_set();
    let _: &[u8] = private_key.as_bytes();

    let signature = MlDsaSignature::from_bytes(parameter_set, encoded)?;
    let _: MlDsaParameterSet = signature.parameter_set();
    let _: &[u8] = signature.as_bytes();
    let _: Vec<u8> = signature.clone().into_bytes();

    let _: MlDsaKeyPair = implementation.keygen_from_seed(&seed)?;
    let _: MlDsaSignature =
        implementation.sign_deterministic(&private_key, message, context)?;
    let _: MlDsaSignature =
        implementation.sign_hedged(&private_key, message, context, rng)?;
    let _: bool = implementation.verify(&public_key, message, context, &signature)?;
    let prehash = PreHashAlgorithm::Sha3_512;
    let _: MlDsaSignature =
        implementation.hash_sign_deterministic(&private_key, message, context, prehash)?;
    let _: MlDsaSignature =
        implementation.hash_sign_hedged(&private_key, message, context, prehash, rng)?;
    let _: bool =
        implementation.hash_verify(&public_key, message, context, prehash, &signature)?;

    let (_public_key, _private_key): (MlDsaPublicKey, MlDsaPrivateKey) =
        key_pair.into_parts();
    Ok(())
}

pub fn variants() {
    let _ = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    let _ = [
        MlDsaError::InvalidPublicKey,
        MlDsaError::InvalidPrivateKey,
        MlDsaError::InvalidSignature,
        MlDsaError::ContextTooLong,
        MlDsaError::ParameterSetMismatch,
        MlDsaError::RandomnessFailure,
        MlDsaError::RejectionLimitExceeded,
        MlDsaError::InternalError,
    ];
    let _ = [
        PreHashAlgorithm::Sha2_224,
        PreHashAlgorithm::Sha2_256,
        PreHashAlgorithm::Sha2_384,
        PreHashAlgorithm::Sha2_512,
        PreHashAlgorithm::Sha2_512_224,
        PreHashAlgorithm::Sha2_512_256,
        PreHashAlgorithm::Sha3_224,
        PreHashAlgorithm::Sha3_256,
        PreHashAlgorithm::Sha3_384,
        PreHashAlgorithm::Sha3_512,
        PreHashAlgorithm::Shake128,
        PreHashAlgorithm::Shake256,
    ];
}
RS

cargo check \
  --manifest-path "${consumer}/Cargo.toml" \
  --quiet

cat >"${consumer}/src/lib.rs" <<'RS'
use pqc_ml_dsa::PreHashAlgorithm;

pub fn unsupported_acvp_helper() {
    let _ = PreHashAlgorithm::from_acvp_name("SHA2-256");
}
RS

if cargo check \
  --manifest-path "${consumer}/Cargo.toml" \
  --quiet >"${consumer}/negative.log" 2>&1; then
  echo "ordinary downstream build unexpectedly used the ACVP-only parser" >&2
  exit 1
fi

if ! rg -q 'no variant or associated item|not found' "${consumer}/negative.log"; then
  echo "negative API contract check failed for an unexpected reason" >&2
  cat "${consumer}/negative.log" >&2
  exit 1
fi

echo "ML-DSA public API and SemVer contract: pass"
