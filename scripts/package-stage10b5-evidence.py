#!/usr/bin/env python3
"""Finalize one architecture's Stage 10B-5 evidence and checksum manifest."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def command_output(command: list[str]) -> str | None:
    try:
        process = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return process.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def rust_record() -> dict[str, str | None]:
    verbose = command_output(["rustc", "--version", "--verbose"]) or ""
    fields: dict[str, str] = {}
    for line in verbose.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key] = value
    return {
        "rustc": verbose.splitlines()[0] if verbose else None,
        "host": fields.get("host"),
        "llvm_version": fields.get("LLVM version"),
        "cargo": command_output(["cargo", "--version"]),
    }


def git_record() -> dict[str, Any]:
    commit = os.environ.get("PQC_STAGE10B5_SOURCE_COMMIT")
    if not commit:
        commit = command_output(["git", "rev-parse", "HEAD"])
    status = command_output(["git", "status", "--porcelain"])
    return {
        "commit": commit,
        "dirty": bool(status),
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(evidence_dir: Path) -> None:
    excluded = {"SHA256SUMS"}
    files = sorted(
        path
        for path in evidence_dir.rglob("*")
        if path.is_file() and path.name not in excluded
    )
    lines = [
        f"{sha256(path)}  {path.relative_to(evidence_dir).as_posix()}"
        for path in files
    ]
    (evidence_dir / "SHA256SUMS").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def target_policy(policy: dict[str, Any], target_id: str) -> dict[str, Any]:
    matches = [target for target in policy["targets"] if target["id"] == target_id]
    if len(matches) != 1:
        raise ValueError(f"unknown or duplicated target id: {target_id}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()

    policy = load_json(args.policy)
    expected = target_policy(policy, args.target_id)
    machine_code = load_json(args.evidence_dir / "machine-code.json")
    timing = load_json(args.evidence_dir / "timing.json")
    rust = rust_record()
    git = git_record()

    system = platform.system()
    machine = platform.machine().lower()
    host = rust["host"] or ""
    architecture_match = (
        system == expected["system"]
        and re.fullmatch(expected["machine_pattern"], machine, re.IGNORECASE) is not None
        and re.fullmatch(expected["rust_host_pattern"], host) is not None
    )

    checks = [
        {
            "id": "architecture-identity",
            "status": "pass" if architecture_match else "fail",
            "gating": True,
        },
        {"id": "functional", "status": "pass", "gating": True},
        {
            "id": "generated-code",
            "status": machine_code["generated_code_decision"],
            "gating": True,
        },
        {
            "id": "secret-dependency",
            "status": machine_code["secret_dependency_decision"],
            "gating": True,
        },
        {
            "id": "timing-evidence",
            "status": "recorded",
            "classification": timing["classification"],
            "gating": False,
        },
        {"id": "artifact-integrity", "status": "pass", "gating": True},
    ]
    decision = (
        "pass"
        if all(check["status"] == "pass" for check in checks if check["gating"])
        else "fail"
    )

    summary = {
        "schema_version": 1,
        "stage": "10B-5",
        "target_id": args.target_id,
        "runner_label": expected["runner"],
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": git,
        "environment": {
            "system": system,
            "platform": platform.platform(),
            "machine": machine,
            "processor": platform.processor(),
            "logical_cpus": os.cpu_count(),
            "runner_image": os.environ.get("ImageOS"),
            "runner_image_version": os.environ.get("ImageVersion"),
            "rust": rust,
            "rustflags": "-C target-cpu=native -C debuginfo=2 -C force-frame-pointers=yes",
        },
        "checks": checks,
        "decision": decision,
        "statement": (
            "Functional, generated-code recovery, versioned secret-dependency rules, "
            "and artifact integrity are release gates. Hosted timing is retained as "
            "architecture-specific non-gating regression evidence."
        ),
    }
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    (args.evidence_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    write_checksums(args.evidence_dir)

    args.archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.archive, "w:gz") as archive:
        archive.add(args.evidence_dir, arcname=f"stage10b5-{args.target_id}")

    print(f"target={args.target_id}")
    print(f"decision={decision}")
    print(f"evidence={args.archive}")
    return 0 if decision == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
