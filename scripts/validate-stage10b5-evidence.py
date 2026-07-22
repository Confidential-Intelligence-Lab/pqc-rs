#!/usr/bin/env python3
"""Validate and combine Stage 10B-5 architecture evidence artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError(f"{path}:{number}: malformed checksum line")
        digest, relative = match.groups()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"{path}:{number}: unsafe checksum path")
        if relative in entries:
            raise ValueError(f"{path}:{number}: duplicated checksum path")
        entries[relative] = digest
    return entries


def verify_manifest(evidence_dir: Path) -> None:
    manifest = evidence_dir / "SHA256SUMS"
    if not manifest.is_file():
        raise ValueError(f"missing checksum manifest: {manifest}")
    entries = parse_manifest(manifest)
    actual = {
        path.relative_to(evidence_dir).as_posix()
        for path in evidence_dir.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if set(entries) != actual:
        missing = sorted(actual - set(entries))
        extra = sorted(set(entries) - actual)
        raise ValueError(
            f"{manifest}: checksum coverage mismatch; missing={missing}; extra={extra}"
        )
    for relative, expected in entries.items():
        observed = sha256(evidence_dir / relative)
        if observed != expected:
            raise ValueError(f"{manifest}: checksum mismatch for {relative}")


def write_manifest(directory: Path) -> None:
    files = sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (directory / "SHA256SUMS").write_text(
        "\n".join(
            f"{sha256(path)}  {path.relative_to(directory).as_posix()}"
            for path in files
        )
        + "\n",
        encoding="utf-8",
    )


def find_summaries(collected: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(collected.rglob("summary.json")):
        summary = load_json(path)
        if summary.get("stage") != "10B-5" or "target_id" not in summary:
            continue
        target_id = summary["target_id"]
        if target_id in found:
            raise ValueError(f"duplicate summary for target {target_id}")
        found[target_id] = (path, summary)
    return found


def validate_target(
    target: dict[str, Any],
    summary_path: Path,
    summary: dict[str, Any],
    expected_commit: str,
) -> None:
    verify_manifest(summary_path.parent)
    if summary.get("schema_version") != 1:
        raise ValueError(f"{summary_path}: unsupported schema version")
    if summary.get("decision") != "pass":
        raise ValueError(f"{summary_path}: target decision is not pass")
    if summary.get("source", {}).get("commit") != expected_commit:
        raise ValueError(f"{summary_path}: source commit mismatch")
    environment = summary.get("environment", {})
    if environment.get("system") != target["system"]:
        raise ValueError(f"{summary_path}: operating-system mismatch")
    if not re.fullmatch(
        target["machine_pattern"],
        str(environment.get("machine", "")),
        re.IGNORECASE,
    ):
        raise ValueError(f"{summary_path}: machine architecture mismatch")
    rust_host = environment.get("rust", {}).get("host", "")
    if not re.fullmatch(target["rust_host_pattern"], str(rust_host)):
        raise ValueError(f"{summary_path}: Rust host mismatch")
    checks = {check["id"]: check for check in summary.get("checks", [])}
    required = {
        "architecture-identity",
        "functional",
        "generated-code",
        "secret-dependency",
        "artifact-integrity",
    }
    if not required.issubset(checks):
        raise ValueError(f"{summary_path}: required checks are missing")
    if any(checks[check_id].get("status") != "pass" for check_id in required):
        raise ValueError(f"{summary_path}: required check did not pass")
    timing = checks.get("timing-evidence")
    if not timing or timing.get("gating") is not False or timing.get("status") != "recorded":
        raise ValueError(f"{summary_path}: timing evidence boundary is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--collected", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()

    policy = load_json(args.policy)
    expected = {target["id"]: target for target in policy["targets"]}
    found = find_summaries(args.collected)
    if set(found) != set(expected):
        raise ValueError(
            "architecture evidence set mismatch; "
            f"expected={sorted(expected)}; found={sorted(found)}"
        )

    rows = []
    for target_id in sorted(expected):
        summary_path, summary = found[target_id]
        validate_target(expected[target_id], summary_path, summary, args.expected_commit)
        timing = next(
            check for check in summary["checks"] if check["id"] == "timing-evidence"
        )
        rows.append({
            "target_id": target_id,
            "runner_label": summary["runner_label"],
            "system": summary["environment"]["system"],
            "machine": summary["environment"]["machine"],
            "rust_host": summary["environment"]["rust"]["host"],
            "rustc": summary["environment"]["rust"]["rustc"],
            "llvm_version": summary["environment"]["rust"]["llvm_version"],
            "timing_classification": timing["classification"],
            "decision": summary["decision"],
        })

    if args.output.exists():
        shutil.rmtree(args.output)
    (args.output / "architectures").mkdir(parents=True)
    (args.output / "target-summaries").mkdir(parents=True)

    for target_id, (summary_path, summary) in found.items():
        shutil.copy2(
            summary_path,
            args.output / "target-summaries" / f"{target_id}.json",
        )
        candidates = list(
            summary_path.parent.parent.glob(f"stage10b5-{target_id}-evidence.tar.gz")
        )
        if len(candidates) != 1:
            raise ValueError(
                f"expected one evidence archive for {target_id}; found {len(candidates)}"
            )
        shutil.copy2(candidates[0], args.output / "architectures" / candidates[0].name)

    aggregate = {
        "schema_version": 1,
        "stage": "10B-5",
        "source_commit": args.expected_commit,
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "targets": rows,
        "decision": "pass",
        "statement": (
            "All required functional, generated-code, secret-dependency, and "
            "artifact-integrity checks passed on the three release architectures. "
            "Timing classifications are retained as non-gating, per-architecture evidence."
        ),
    }
    (args.output / "summary.json").write_text(
        json.dumps(aggregate, indent=2) + "\n",
        encoding="utf-8",
    )
    write_manifest(args.output)
    verify_manifest(args.output)

    args.archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(args.archive, "w:gz") as archive:
        archive.add(args.output, arcname="stage10b5-cross-architecture")

    print("decision=pass")
    print(f"targets={','.join(sorted(expected))}")
    print(f"evidence={args.archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
