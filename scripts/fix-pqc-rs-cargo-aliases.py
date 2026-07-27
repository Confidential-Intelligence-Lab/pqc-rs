#!/usr/bin/env python3

from pathlib import Path
import re

ROOT = Path.cwd()

CRATES = {
    "pqc-core": ("pqc-rs-core", "pqc_core"),
    "pqc-ml-kem": ("pqc-rs-ml-kem", "pqc_ml_kem"),
    "pqc-hpke": ("pqc-rs-hpke", "pqc_hpke"),
    "pqc-hybrid": ("pqc-rs-hybrid", "pqc_hybrid"),
    "pqc-ml-dsa": ("pqc-rs-ml-dsa", "pqc_ml_dsa"),
    "pqc-slh-dsa": ("pqc-rs-slh-dsa", "pqc_slh_dsa"),
    "pqc-test-harness": ("pqc-rs-test-harness", "pqc_test_harness"),
}

VERSION = "0.4.0"


def section_bounds(text: str, section: str) -> tuple[int, int]:
    marker = f"[{section}]"
    start = text.find(marker)

    if start < 0:
        raise SystemExit(f"Missing [{section}]")

    end = text.find("\n[", start + len(marker))

    if end < 0:
        end = len(text)

    return start, end


def replace_workspace_dependency(
    text: str,
    alias: str,
    package: str,
    path: str,
) -> str:
    start, end = section_bounds(text, "workspace.dependencies")
    body = text[start:end]

    pattern = re.compile(
        rf"(?m)^{re.escape(alias)}\s*=.*$"
    )

    replacement = (
        f'{alias} = {{ package = "{package}", '
        f'path = "{path}", version = "{VERSION}" }}'
    )

    if pattern.search(body):
        body = pattern.sub(replacement, body, count=1)
    else:
        body = body.rstrip() + "\n" + replacement + "\n"

    return text[:start] + body + text[end:]


def ensure_lib_name(text: str, lib_name: str) -> str:
    lib_match = re.search(r"(?m)^\[lib\]\s*$", text)

    if lib_match:
        start = lib_match.start()
        end = text.find("\n[", lib_match.end())

        if end < 0:
            end = len(text)

        body = text[start:end]

        if re.search(r"(?m)^name\s*=", body):
            body = re.sub(
                r'(?m)^name\s*=.*$',
                f'name = "{lib_name}"',
                body,
                count=1,
            )
        else:
            body = body.rstrip() + f'\nname = "{lib_name}"\n'

        return text[:start] + body + text[end:]

    return text.rstrip() + f'\n\n[lib]\nname = "{lib_name}"\n'


def remove_ignored_package_keys(text: str) -> str:
    # Handles dependency tables such as:
    #
    # [dependencies.pqc-core]
    # workspace = true
    # package = "pqc-rs-core"
    #
    # The package mapping belongs in [workspace.dependencies], not here.
    lines = text.splitlines()
    output = []
    in_dependency_table = False
    workspace_dependency_table = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("[") and stripped.endswith("]"):
            in_dependency_table = bool(
                re.match(
                    r"^\[(?:dev-|build-)?dependencies\.[^\]]+\]$",
                    stripped,
                )
            )
            workspace_dependency_table = False

        if (
            in_dependency_table
            and stripped.startswith("package")
            and "=" in stripped
        ):
            continue

        output.append(line)

    return "\n".join(output) + "\n"


root_manifest = ROOT / "Cargo.toml"
root_text = root_manifest.read_text(encoding="utf-8")

for directory, (package_name, _) in CRATES.items():
    path = f"crates/{directory}"

    root_text = replace_workspace_dependency(
        root_text,
        directory,
        package_name,
        path,
    )

root_manifest.write_text(root_text, encoding="utf-8")
print(f"updated {root_manifest}")

for directory, (_, lib_name) in CRATES.items():
    manifest = ROOT / "crates" / directory / "Cargo.toml"

    if not manifest.exists():
        print(f"skipped missing {manifest}")
        continue

    text = manifest.read_text(encoding="utf-8")
    text = remove_ignored_package_keys(text)
    text = ensure_lib_name(text, lib_name)
    manifest.write_text(text, encoding="utf-8")
    print(f"updated {manifest}")

print("Cargo aliases and Rust library names repaired.")
