#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path.cwd()
RC_VERSION = "0.4.0"
REPOSITORY = "https://github.com/Confidential-Intelligence-Lab/pqc-rs"
AUTHOR = "Rosario Cammarota"

PACKAGE_RENAMES = {
    "pqc-core": "pqc-rs-core",
    "pqc-ml-kem": "pqc-rs-ml-kem",
    "pqc-hpke": "pqc-rs-hpke",
    "pqc-hybrid": "pqc-rs-hybrid",
    "pqc-ml-dsa": "pqc-rs-ml-dsa",
    "pqc-slh-dsa": "pqc-rs-slh-dsa",
    "pqc-test-harness": "pqc-rs-test-harness",
}

PUBLISHABLE = {
    "pqc-core": {
        "package": "pqc-rs-core",
        "description": "Core traits, byte types, errors, and secret containers for PQC-rs.",
        "keywords": ["post-quantum", "cryptography", "pqc", "rust"],
    },
    "pqc-ml-kem": {
        "package": "pqc-rs-ml-kem",
        "description": "Standards-focused Rust implementation of ML-KEM for PQC-rs.",
        "keywords": ["post-quantum", "cryptography", "ml-kem", "kem", "rust"],
    },
    "pqc-hpke": {
        "package": "pqc-rs-hpke",
        "description": "HPKE with ML-KEM and post-quantum/traditional hybrid key encapsulation for PQC-rs.",
        "keywords": ["post-quantum", "cryptography", "hpke", "ml-kem", "rust"],
    },
}

PRIVATE = {
    "pqc-hybrid",
    "pqc-test-harness",
    "pqc-ml-dsa",
    "pqc-slh-dsa",
}


def read(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"Missing required file: {path}")
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str) -> None:
    path.write_text(text.rstrip() + "\n", encoding="utf-8")
    print(f"updated {path}")


def section_bounds(text: str, section: str) -> tuple[int, int]:
    marker = f"[{section}]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"Missing [{section}] section")
    end = text.find("\n[", start + len(marker))
    if end < 0:
        end = len(text)
    return start, end


def set_field(text: str, section: str, key: str, value: str) -> str:
    start, end = section_bounds(text, section)
    body = text[start:end]
    pattern = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    line = f"{key} = {value}"
    if pattern.search(body):
        body = pattern.sub(line, body, count=1)
    else:
        body = body.rstrip() + "\n" + line + "\n"
    return text[:start] + body + text[end:]


def ensure_package_field(text: str, key: str, value: str) -> str:
    start, end = section_bounds(text, "package")
    body = text[start:end]
    direct = re.compile(rf"(?m)^{re.escape(key)}\s*=.*$")
    inherited = re.compile(rf"(?m)^{re.escape(key)}\.workspace\s*=\s*true\s*$")

    if direct.search(body):
        body = direct.sub(f"{key} = {value}", body, count=1)
    elif inherited.search(body):
        if key in {"version", "edition", "license", "repository", "authors", "rust-version"}:
            return text
        body = body.rstrip() + f"\n{key} = {value}\n"
    else:
        body = body.rstrip() + f"\n{key} = {value}\n"

    return text[:start] + body + text[end:]


def update_dependency_aliases(text: str) -> str:
    for old, new in PACKAGE_RENAMES.items():
        # Preserve the local dependency key to avoid source-code import churn,
        # but identify the renamed package with `package =`.
        inline = re.compile(
            rf'(?m)^({re.escape(old)}\s*=\s*\{{)([^}}]*)(\}})$'
        )

        def repl(match: re.Match[str]) -> str:
            body = match.group(2)
            if "package =" not in body:
                body = f' package = "{new}",' + body
            body = re.sub(
                r'\bversion\s*=\s*"[^"]+"',
                f'version = "{RC_VERSION}"',
                body,
            )
            return match.group(1) + body + match.group(3)

        text = inline.sub(repl, text)

        # Workspace dependency definitions may use the renamed package directly.
        text = re.sub(
            rf'(?m)^{re.escape(old)}\s*=\s*"[^"]+"$',
            f'{old} = {{ package = "{new}", version = "{RC_VERSION}" }}',
            text,
        )
    return text


def patch_root() -> None:
    path = ROOT / "Cargo.toml"
    text = read(path)
    text = set_field(text, "workspace.package", "authors", f'["{AUTHOR}"]')
    text = set_field(text, "workspace.package", "repository", f'"{REPOSITORY}"')
    text = set_field(text, "workspace.package", "homepage", f'"{REPOSITORY}"')
    text = set_field(text, "workspace.package", "version", f'"{RC_VERSION}"')
    text = update_dependency_aliases(text)
    write(path, text)


def patch_crate(directory: str) -> None:
    path = ROOT / "crates" / directory / "Cargo.toml"
    text = read(path)
    new_name = PACKAGE_RENAMES[directory]
    text = ensure_package_field(text, "name", f'"{new_name}"')
    text = update_dependency_aliases(text)

    if directory in PUBLISHABLE:
        metadata = PUBLISHABLE[directory]
        text = ensure_package_field(text, "description", f'"{metadata["description"]}"')
        text = ensure_package_field(text, "readme", '"../../README.md"')
        text = ensure_package_field(text, "categories", '["cryptography"]')
        keywords = ", ".join(f'"{item}"' for item in metadata["keywords"])
        text = ensure_package_field(text, "keywords", f"[{keywords}]")

        start, end = section_bounds(text, "package")
        body = text[start:end]
        body = re.sub(r"(?m)^publish\s*=\s*false\s*\n?", "", body)
        text = text[:start] + body + text[end:]
    else:
        text = ensure_package_field(text, "publish", "false")

    write(path, text)


def patch_docs_and_scripts() -> None:
    replacements = {
        "pqc-core": "pqc-rs-core",
        "pqc-ml-kem": "pqc-rs-ml-kem",
        "pqc-hpke": "pqc-rs-hpke",
    }

    for path in [
        ROOT / "README.md",
        ROOT / "CHANGELOG.md",
        ROOT / "docs" / "release-checklist.md",
        ROOT / "scripts" / "check-release-metadata.py",
        ROOT / "scripts" / "run-stage8f-release-gate.sh",
        ROOT / "scripts" / "package-release-candidate.sh",
    ]:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new)
        write(path, text)


def main() -> None:
    if not (ROOT / "Cargo.toml").exists():
        raise SystemExit("Run from the repository root.")

    patch_root()

    for directory in PACKAGE_RENAMES:
        crate_manifest = ROOT / "crates" / directory / "Cargo.toml"
        if crate_manifest.exists():
            patch_crate(directory)

    patch_docs_and_scripts()

    print()
    print("PQC-rs package migration complete.")
    print("Directory names were intentionally left unchanged.")
    print("Next:")
    print("  cargo update --workspace")
    print("  cargo metadata --no-deps")
    print("  cargo fmt --all")
    print("  cargo clippy --workspace --all-targets --all-features -- -D warnings")
    print("  cargo test --workspace --all-features")


if __name__ == "__main__":
    main()
