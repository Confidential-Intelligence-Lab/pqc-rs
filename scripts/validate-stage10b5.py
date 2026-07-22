#!/usr/bin/env python3
"""Validate the static Stage 10B-5 policy, workflow, and audit surface."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT / "sidechannel/stage10b5/policy.json"
WORKFLOW_PATH = ROOT / ".github/workflows/stage10b5-cross-architecture.yml"
DOCUMENT_PATH = ROOT / "docs/security/STAGE10B5_CROSS_ARCHITECTURE.md"
EXPECTED_TARGETS = {
    "linux-x86_64": "ubuntu-24.04",
    "linux-aarch64": "ubuntu-24.04-arm",
    "apple-aarch64": "macos-15",
}
REQUIRED_SCRIPTS = (
    "scripts/analyze-stage10b5-machine-code.py",
    "scripts/analyze-stage10b5-timing.py",
    "scripts/package-stage10b5-evidence.py",
    "scripts/run-stage10b5-cross-architecture.sh",
    "scripts/validate-stage10b5-evidence.py",
    "scripts/validate-stage10b5.py",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def fail(message: str) -> None:
    raise SystemExit(f"Stage 10B-5 validation failed: {message}")


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema_version") != 1:
        fail("unsupported policy schema")
    targets = policy.get("targets")
    if not isinstance(targets, list):
        fail("targets must be an array")
    observed_targets = {target.get("id"): target.get("runner") for target in targets}
    if observed_targets != EXPECTED_TARGETS:
        fail(f"target matrix mismatch: {observed_targets}")
    for target in targets:
        for key in ("system", "machine_pattern", "rust_host_pattern"):
            if not target.get(key):
                fail(f"target {target.get('id')} lacks {key}")
        re.compile(target["machine_pattern"])
        re.compile(target["rust_host_pattern"])

    binaries = policy.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        fail("binary policy is empty")
    binary_names = set()
    for binary in binaries:
        name = binary.get("name")
        if not name or name in binary_names:
            fail(f"invalid or duplicate binary name: {name}")
        binary_names.add(name)
        source = ROOT / "crates/pqc-test-harness/src/bin" / f"{name}.rs"
        if not source.is_file():
            fail(f"audit binary source does not exist: {source}")
        source_text = source.read_text(encoding="utf-8")
        wrappers = binary.get("wrappers")
        if not isinstance(wrappers, list) or not wrappers:
            fail(f"binary {name} has no wrappers")
        wrapper_names = set()
        for wrapper in wrappers:
            wrapper_name = wrapper.get("name")
            if not wrapper_name or wrapper_name in wrapper_names:
                fail(f"binary {name} has an invalid wrapper")
            wrapper_names.add(wrapper_name)
            if f"fn {wrapper_name}" not in source_text:
                fail(f"wrapper {wrapper_name} is absent from {source}")
            if wrapper.get("control_policy") not in {
                "branchless",
                "public-control",
                "zeroization",
            }:
                fail(f"wrapper {wrapper_name} has an invalid control policy")

    timing = policy.get("timing", {})
    if timing.get("gating") is not False:
        fail("hosted timing must remain non-gating")
    if float(timing.get("threshold_absolute_welch_t", 0)) <= 0:
        fail("timing threshold must be positive")


def validate_workflow() -> None:
    if not WORKFLOW_PATH.is_file():
        fail(f"missing workflow: {WORKFLOW_PATH}")
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    for target_id, runner in EXPECTED_TARGETS.items():
        if target_id not in text or runner not in text:
            fail(f"workflow omits {target_id} / {runner}")
    for marker in (
        "paths:",
        "workflow_dispatch:",
        "fail-fast: false",
        "if: always()",
        "validate-stage10b5-evidence.py",
        "merge-multiple: false",
    ):
        if marker not in text:
            fail(f"workflow omits required marker: {marker}")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("uses:") and "- uses:" not in stripped:
            continue
        if not re.search(r"@[0-9a-f]{40}(?:\s|$)", stripped):
            fail(f"workflow action is not pinned to a full SHA: {stripped}")


def validate_files() -> None:
    if not DOCUMENT_PATH.is_file():
        fail(f"missing documentation: {DOCUMENT_PATH}")
    for relative in REQUIRED_SCRIPTS:
        path = ROOT / relative
        if not path.is_file():
            fail(f"missing script: {relative}")
        if not os.access(path, os.X_OK):
            fail(f"script is not executable: {relative}")


def main() -> int:
    validate_policy(load_json(POLICY_PATH))
    validate_workflow()
    validate_files()
    print("Stage 10B-5 static validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
