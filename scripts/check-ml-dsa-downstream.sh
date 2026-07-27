#!/usr/bin/env bash
set -euo pipefail

readonly repo_root="$(git rev-parse --show-toplevel)"
readonly package_name="pqc-rs-ml-dsa"
readonly package_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

cd "${repo_root}"

package_version="$(
  cargo metadata --locked --format-version 1 --no-deps |
    python3 -c '
import json
import sys

metadata = json.load(sys.stdin)
matches = [
    package["version"]
    for package in metadata["packages"]
    if package["name"] == "pqc-rs-ml-dsa"
]
if len(matches) != 1:
    raise SystemExit("expected exactly one pqc-rs-ml-dsa package")
print(matches[0])
'
)"
readonly package_version

consumer_root="$(mktemp -d "${TMPDIR:-/tmp}/pqc-ml-dsa-downstream.XXXXXX")"
readonly consumer_root
trap 'rm -rf -- "${consumer_root}"' EXIT

mkdir -p \
  "${consumer_root}/archive" \
  "${consumer_root}/consumer/src"

readonly package_list="${consumer_root}/package-list.txt"
cargo package \
  --locked \
  --allow-dirty \
  -p "${package_name}" \
  --list >"${package_list}"

for required in \
  "Cargo.toml" \
  "Cargo.toml.orig" \
  "README.md" \
  "src/api.rs" \
  "src/lib.rs"; do
  grep -Fx "${required}" "${package_list}" >/dev/null ||
    {
      echo "required package file is absent: ${required}" >&2
      exit 1
    }
done

if grep -E \
  '(^|/)([.]git|target|vectors|evidence|audit|scripts)(/|$)' \
  "${package_list}" >/dev/null; then
  echo "repository-only content escaped into the ML-DSA package" >&2
  exit 1
fi

cargo package --locked --allow-dirty -p "${package_name}"

readonly package_archive="${package_target_dir}/package/${package_name}-${package_version}.crate"
if [[ ! -f "${package_archive}" ]]; then
  echo "missing package archive: ${package_archive}" >&2
  exit 1
fi

tar -xzf "${package_archive}" -C "${consumer_root}/archive"

readonly packaged_crate="${consumer_root}/archive/${package_name}-${package_version}"
if ! cmp -s \
  "${repo_root}/crates/pqc-ml-dsa/README.md" \
  "${packaged_crate}/README.md"; then
  echo "packaged README.md does not match the crate README" >&2
  exit 1
fi

package_metadata="$(
  cargo metadata \
    --format-version 1 \
    --no-deps \
    --manifest-path "${packaged_crate}/Cargo.toml"
)"

python3 - "${package_metadata}" <<'PY'
import json
import sys

metadata = json.loads(sys.argv[1])
packages = metadata["packages"]
if len(packages) != 1:
    raise SystemExit("expected one package in extracted ML-DSA metadata")
matches = [
    dependency
    for dependency in packages[0]["dependencies"]
    if dependency["name"] == "pqc-rs-core"
]
if len(matches) != 1:
    raise SystemExit("normalized package lost the pqc-rs-core dependency")
dependency = matches[0]
if dependency.get("path") is not None:
    raise SystemExit("normalized package retained a workspace path for pqc-core")
if dependency.get("req") != "^0.4.0":
    raise SystemExit("normalized package does not require stable pqc-rs-core 0.4.0")

for dependency in packages[0]["dependencies"]:
    if dependency.get("path") is not None:
        raise SystemExit(
            f"normalized package retained a path dependency: {dependency['name']}"
        )
    source = dependency.get("source")
    if source is not None and not source.startswith("registry+"):
        raise SystemExit(
            f"normalized package retained a non-registry dependency: "
            f"{dependency['name']} ({source})"
        )

docs_rs = packages[0].get("metadata", {}).get("docs", {}).get("rs")
expected_docs_rs = {
    "all-features": True,
    "rustdoc-args": ["--cfg", "docsrs", "-D", "warnings"],
}
if docs_rs != expected_docs_rs:
    raise SystemExit(
        f"normalized package lost the docs.rs contract: {docs_rs!r}"
    )

if packages[0].get("publish") != []:
    raise SystemExit(
        "normalized package metadata does not preserve the publication lock"
    )
PY

cat >"${consumer_root}/consumer/Cargo.toml" <<TOML
[package]
name = "pqc-rs-ml-dsa-downstream-check"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
pqc-rs-ml-dsa = { path = "../archive/${package_name}-${package_version}" }
TOML

cat >"${consumer_root}/consumer/src/main.rs" <<'RS'
use pqc_ml_dsa::{
    MlDsa, MlDsaKeyGenSeed, MlDsaParameterSet, MlDsaPrivateKey, MlDsaPublicKey,
    MlDsaSignature, PreHashAlgorithm, ML_DSA_KEYGEN_SEED_BYTES,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parameter_sets = [
        MlDsaParameterSet::MlDsa44,
        MlDsaParameterSet::MlDsa65,
        MlDsaParameterSet::MlDsa87,
    ];
    let message = b"packaged downstream consumer";
    let context = b"stage-15a-8";

    for (index, parameter_set) in parameter_sets.into_iter().enumerate() {
        let implementation = MlDsa::new(parameter_set);
        let seed = MlDsaKeyGenSeed::from_bytes(
            parameter_set,
            [0x40 + index as u8; ML_DSA_KEYGEN_SEED_BYTES],
        );
        let key_pair = seed.expand()?;

        let public_key =
            MlDsaPublicKey::from_bytes(parameter_set, key_pair.public_key().as_bytes())?;
        let private_key =
            MlDsaPrivateKey::from_bytes(parameter_set, key_pair.private_key().as_bytes())?;

        assert_eq!(public_key.as_bytes().len(), implementation.public_key_bytes());
        assert_eq!(private_key.as_bytes().len(), implementation.private_key_bytes());

        let encoded_signature = implementation
            .sign_deterministic(&private_key, message, context)?
            .into_bytes();
        let signature = MlDsaSignature::from_bytes(parameter_set, &encoded_signature)?;

        assert_eq!(signature.as_bytes().len(), implementation.signature_bytes());
        assert!(implementation.verify(&public_key, message, context, &signature)?);
        assert!(!implementation.verify(&public_key, b"modified", context, &signature)?);

        let hash_signature = implementation.hash_sign_deterministic(
            &private_key,
            message,
            context,
            PreHashAlgorithm::Sha2_256,
        )?;
        assert!(implementation.hash_verify(
            &public_key,
            message,
            context,
            PreHashAlgorithm::Sha2_256,
            &hash_signature,
        )?);
    }

    println!("packaged ML-DSA downstream consumer: pass");
    Ok(())
}
RS

readonly consumer_manifest="${consumer_root}/consumer/Cargo.toml"
readonly consumer_target="${consumer_root}/target"

CARGO_TARGET_DIR="${consumer_target}" \
  cargo test \
    --locked \
    --manifest-path "${packaged_crate}/Cargo.toml" \
    --all-features

CARGO_TARGET_DIR="${consumer_target}" \
  env \
    DOCS_RS=1 \
    RUSTDOCFLAGS="--cfg docsrs -D warnings" \
  cargo doc \
    --locked \
    --manifest-path "${packaged_crate}/Cargo.toml" \
    --all-features \
    --no-deps
CARGO_TARGET_DIR="${consumer_target}" \
  cargo generate-lockfile --manifest-path "${consumer_manifest}"
CARGO_TARGET_DIR="${consumer_target}" \
  cargo run --locked --manifest-path "${consumer_manifest}"

readonly publish_dry_run="${consumer_root}/publish-dry-run"
cp -R "${packaged_crate}" "${publish_dry_run}"
rm -f "${publish_dry_run}/Cargo.toml.orig"

python3 - "${publish_dry_run}/Cargo.toml" <<'PY'
from pathlib import Path
import re
import sys

manifest_path = Path(sys.argv[1])
manifest = manifest_path.read_text()
updated, replacements = re.subn(
    r"(?m)^publish\s*=\s*(?:false|\[\s*\])\s*$",
    'publish = ["crates-io"]',
    manifest,
    count=1,
)
if replacements != 1:
    raise SystemExit(
        "could not replace the disposable extracted crate publication lock"
    )
manifest_path.write_text(updated)
PY

CARGO_TARGET_DIR="${consumer_target}" \
  cargo publish \
    --dry-run \
    --locked \
    --allow-dirty \
    --registry crates-io \
    --manifest-path "${publish_dry_run}/Cargo.toml"

echo "ML-DSA package reconstruction, docs.rs, downstream-consumer, and publish dry-run validation passed."
