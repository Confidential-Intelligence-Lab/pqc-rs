#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path.cwd()
REPOSITORY = "https://github.com/Confidential-Intelligence-Lab/pqc-rs"
HOMEPAGE = REPOSITORY
AUTHOR = "Rosario Cammarota"
RC_VERSION = "0.4.0"

PUBLISHABLE = {
    "pqc-core": (
        "Core types, traits, errors, and secret containers for the PQC-rs cryptography workspace.",
        ["post-quantum", "cryptography", "pqc", "rust"],
        "../../README.md",
    ),
    "pqc-ml-kem": (
        "Standards-focused Rust implementation of ML-KEM for PQC-rs.",
        ["post-quantum", "cryptography", "ml-kem", "kem", "rust"],
        "../../README.md",
    ),
    "pqc-ml-dsa": (
        "FIPS 204 ML-DSA implementation for PQC-rs",
        ["post-quantum", "cryptography", "ml-dsa", "signatures", "rust"],
        "README.md",
    ),
    "pqc-hpke": (
        "HPKE with ML-KEM and post-quantum/traditional hybrid key encapsulation for PQC-rs.",
        ["post-quantum", "cryptography", "hpke", "ml-kem", "rust"],
        "../../README.md",
    ),
}
PRIVATE = {"pqc-hybrid", "pqc-test-harness", "pqc-slh-dsa"}
INTERNAL = {
    "pqc-core", "pqc-ml-kem", "pqc-hpke", "pqc-hybrid",
    "pqc-test-harness", "pqc-ml-dsa", "pqc-slh-dsa",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def read(path: Path) -> str:
    if not path.exists():
        fail(f"Missing required file: {path}")
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    print(f"updated {path}")


def section_bounds(text: str, section: str) -> tuple[int, int]:
    marker = f"[{section}]"
    start = text.find(marker)
    if start < 0:
        fail(f"Missing [{section}] section")
    end = text.find("\n[", start + len(marker))
    return start, len(text) if end < 0 else end


def set_field(text: str, section: str, key: str, rendered: str) -> str:
    start, end = section_bounds(text, section)
    body = text[start:end]
    direct = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    inherited = re.compile(rf"(?m)^{re.escape(key)}\.workspace\s*=.*$")
    if direct.search(body):
        body = direct.sub(f"{key} = {rendered}", body, count=1)
    elif inherited.search(body):
        return text
    else:
        body = body.rstrip() + f"\n{key} = {rendered}\n"
    return text[:start] + body + text[end:]


def remove_root_dev_dependencies(text: str) -> str:
    return re.sub(r"\n\[dev-dependencies\]\n(?:(?!\n\[).)*", "\n", text, flags=re.S)


def update_internal_versions(text: str) -> str:
    for crate in INTERNAL:
        inline = re.compile(
            rf'(?m)^({re.escape(crate)}\s*=\s*\{{[^}}]*?\bversion\s*=\s*")([^"]+)("[^}}]*\}})$'
        )
        text = inline.sub(rf'\g<1>{RC_VERSION}\g<3>', text)
        plain = re.compile(rf'(?m)^({re.escape(crate)}\s*=\s*")([^"]+)("\s*)$')
        text = plain.sub(rf'\g<1>{RC_VERSION}\g<3>', text)
    return text


def patch_root() -> None:
    path = ROOT / "Cargo.toml"
    text = read(path)
    text = set_field(text, "workspace.package", "authors", f'["{AUTHOR}"]')
    text = set_field(text, "workspace.package", "repository", f'"{REPOSITORY}"')
    text = set_field(text, "workspace.package", "homepage", f'"{HOMEPAGE}"')
    text = set_field(text, "workspace.package", "version", f'"{RC_VERSION}"')
    text = update_internal_versions(text)
    text = remove_root_dev_dependencies(text)
    write(path, text)


def patch_publishable(
    crate: str,
    description: str,
    keywords: list[str],
    readme: str,
) -> None:
    path = ROOT / "crates" / crate / "Cargo.toml"
    text = read(path)
    text = set_field(text, "package", "description", f'"{description}"')
    text = set_field(text, "package", "readme", f'"{readme}"')
    text = set_field(text, "package", "categories", '["cryptography"]')
    rendered_keywords = "[" + ", ".join(f'"{item}"' for item in keywords) + "]"
    text = set_field(text, "package", "keywords", rendered_keywords)
    start, end = section_bounds(text, "package")
    body = re.sub(r"(?m)^publish\s*=\s*false\s*\n?", "", text[start:end])
    text = text[:start] + body + text[end:]
    text = update_internal_versions(text)
    write(path, text)


def patch_private(crate: str) -> None:
    path = ROOT / "crates" / crate / "Cargo.toml"
    if not path.exists():
        print(f"skipped missing private crate: {path}")
        return
    text = set_field(read(path), "package", "publish", "false")
    text = update_internal_versions(text)
    write(path, text)


def patch_other_manifests() -> None:
    for path in (ROOT / "crates").glob("*/Cargo.toml"):
        crate = path.parent.name
        if crate in PUBLISHABLE or crate in PRIVATE:
            continue
        write(path, update_internal_versions(read(path)))


def write_release_scripts() -> None:
    scripts = ROOT / "scripts"
    scripts.mkdir(exist_ok=True)

    package_script = scripts / "package-release-candidate.sh"
    package_script.write_text("""#!/usr/bin/env bash
set -euo pipefail

mkdir -p target/release-candidate
rm -f target/release-candidate/*.crate

cargo package -p pqc-rs-core --list > target/release-candidate/pqc-rs-core-package-list.txt
cargo package -p pqc-rs-core

for crate in pqc-rs-ml-kem pqc-rs-ml-dsa pqc-rs-hpke; do
  cargo package -p \"${crate}\" --list > \"target/release-candidate/${crate}-package-list.txt\"
  cargo package -p \"${crate}\" --no-verify
done

cp target/package/*.crate target/release-candidate/

{
  date -u
  rustc -Vv
  cargo -V
  git rev-parse HEAD
  git status --short
} > target/release-candidate/build-record.txt

echo \"Release candidate artifacts written to target/release-candidate/\"
""", encoding="utf-8")
    package_script.chmod(0o755)
    print(f"updated {package_script}")

    gate_script = scripts / "run-stage8f-release-gate.sh"
    gate_script.write_text("""#!/usr/bin/env bash
set -euo pipefail

python3 scripts/check-release-metadata.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS=\"-D warnings\" cargo doc --workspace --all-features --no-deps
cargo deny check
cargo audit

cargo run -p pqc-test-harness --bin ml-kem-acvp-keygen --release
cargo run -p pqc-test-harness --bin ml-kem-acvp-encapsulation --release
cargo run -p pqc-test-harness --bin ml-kem-acvp-decapsulation --release
cargo run -p pqc-test-harness --bin ml-kem-acvp-key-check --release
cargo run -p pqc-test-harness --bin hpke-pq-base-vectors --release
cargo run -p pqc-test-harness --bin hpke-pq-hybrid-vectors --release

cargo package -p pqc-rs-core
cargo package -p pqc-rs-ml-kem --no-verify
cargo package -p pqc-rs-ml-dsa --no-verify
cargo package -p pqc-rs-hpke --no-verify

echo \"Stage 8F release gate passed.\"
""", encoding="utf-8")
    gate_script.chmod(0o755)
    print(f"updated {gate_script}")


def check_licenses() -> None:
    if not any((ROOT / name).exists() for name in ("LICENSE", "LICENSE-MIT", "LICENSE-APACHE")):
        print("WARNING: add LICENSE-MIT and LICENSE-APACHE before publishing.", file=sys.stderr)


def main() -> None:
    if not (ROOT / "Cargo.toml").exists():
        fail("Run this script from the repository root.")

    patch_root()
    for crate, (description, keywords, readme) in PUBLISHABLE.items():
        patch_publishable(crate, description, keywords, readme)
    for crate in PRIVATE:
        patch_private(crate)
    patch_other_manifests()
    write_release_scripts()
    check_licenses()

    print("\nPre-release changes applied.")
    print("Run next:")
    print("  cargo update --workspace")
    print("  cargo fmt --all")
    print("  python3 scripts/check-release-metadata.py")
    print("  cargo clippy --workspace --all-targets --all-features -- -D warnings")
    print("  cargo test --workspace --all-features")
    print("  ./scripts/run-stage8f-release-gate.sh")
    print("  ./scripts/package-release-candidate.sh")


if __name__ == "__main__":
    main()
