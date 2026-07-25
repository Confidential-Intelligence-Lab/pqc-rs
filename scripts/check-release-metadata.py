#!/usr/bin/env python3
from pathlib import Path
import sys
import tomllib


errors = []


def load_manifest(path):
    if not path.is_file():
        errors.append(f"{path}: manifest is missing")
        return {}

    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        errors.append(f"{path}: cannot read manifest: {error}")
        return {}


root = load_manifest(Path("Cargo.toml"))
workspace_package = root.get("workspace", {}).get("package", {})

for field in (
    "authors",
    "repository",
    "license",
    "edition",
    "rust-version",
    "version",
):
    value = workspace_package.get(field)
    unresolved = (
        value is None
        or (
            isinstance(value, str)
            and ("TODO" in value or not value.strip())
        )
        or (
            isinstance(value, list)
            and any(
                not isinstance(item, str)
                or "TODO" in item
                or not item.strip()
                for item in value
            )
        )
    )
    if unresolved:
        errors.append(
            f"workspace.package.{field} is missing or unresolved"
        )


public_crates = {
    "pqc-rs-core": "pqc-core",
    "pqc-rs-ml-kem": "pqc-ml-kem",
    "pqc-rs-ml-dsa": "pqc-ml-dsa",
    "pqc-rs-hpke": "pqc-hpke",
}

private_crates = {
    "pqc-rs-hybrid": "pqc-hybrid",
    "pqc-rs-slh-dsa": "pqc-slh-dsa",
    "pqc-rs-test-harness": "pqc-test-harness",
}


for package_name, directory in public_crates.items():
    manifest = Path("crates") / directory / "Cargo.toml"
    package = load_manifest(manifest).get("package", {})

    if package.get("name") != package_name:
        errors.append(
            f"{manifest}: expected package name {package_name!r}"
        )
    if package.get("publish") is False:
        errors.append(
            f"{manifest}: publish=false for release crate"
        )


for package_name, directory in private_crates.items():
    manifest = Path("crates") / directory / "Cargo.toml"
    package = load_manifest(manifest).get("package", {})

    if package.get("name") != package_name:
        errors.append(
            f"{manifest}: expected package name {package_name!r}"
        )
    if package.get("publish") is not False:
        errors.append(f"{manifest}: expected publish=false")


if errors:
    print("Release metadata check failed:")
    for error in errors:
        print("-", error)
    sys.exit(1)

print("Release metadata check passed.")
