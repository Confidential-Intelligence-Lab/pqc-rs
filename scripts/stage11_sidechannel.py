#!/usr/bin/env python3
"""Stage 11 systematic side-channel experiment runner.

Uses JSON experiment manifests and emits JSON/Markdown reports without external
Python dependencies. This is regression infrastructure, not a proof of constant
time behavior.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shlex
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be a JSON object")
    return value


def validate_manifest(path: Path, manifest: dict[str, Any]) -> None:
    required = {
        "schema_version", "id", "description", "command", "repetitions",
        "timeout_seconds", "parser", "policy", "enabled",
    }
    missing = sorted(required - manifest.keys())
    if missing:
        raise ValueError(f"{path}: missing fields: {', '.join(missing)}")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"{path}: unsupported schema_version")
    if not isinstance(manifest["command"], list) or not manifest["command"]:
        raise ValueError(f"{path}: command must be a non-empty string array")
    if int(manifest["repetitions"]) < 1:
        raise ValueError(f"{path}: repetitions must be positive")
    parser = manifest["parser"]
    parser_type = parser.get("type")
    if parser_type == "regex":
        if not parser.get("pattern"):
            raise ValueError(f"{path}: regex parser requires pattern")
        re.compile(parser["pattern"])
    elif parser_type != "exit_status":
        raise ValueError(f"{path}: parser type must be regex or exit_status")
    if parser.get("skip_pattern"):
        re.compile(parser["skip_pattern"])
    policy = manifest["policy"]
    if "minimum_successful_repetitions" not in policy:
        raise ValueError(f"{path}: incomplete policy")
    if parser_type == "regex" and "maximum" not in policy and "minimum" not in policy:
        raise ValueError(f"{path}: regex policy requires maximum and/or minimum")


def git_value(args: list[str]) -> str | None:
    try:
        proc = subprocess.run(["git", *args], check=True, capture_output=True,
                              text=True, timeout=10)
        return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def command_version(command: list[str]) -> str | None:
    try:
        proc = subprocess.run(command, check=True, capture_output=True, text=True,
                              timeout=10)
        return proc.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def environment_record() -> dict[str, Any]:
    return {
        "captured_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "platform": platform.platform(), "system": platform.system(),
        "release": platform.release(), "machine": platform.machine(),
        "processor": platform.processor(), "python": sys.version.split()[0],
        "cpu_count": os.cpu_count(), "git_commit": git_value(["rev-parse", "HEAD"]),
        "git_dirty": bool(git_value(["status", "--porcelain"])),
        "rustc": command_version(["rustc", "--version"]),
        "cargo": command_version(["cargo", "--version"]),
    }


def parse_metric(output: str, parser: dict[str, Any]) -> float:
    matches = re.findall(parser["pattern"], output,
                         flags=re.IGNORECASE | re.MULTILINE)
    if not matches:
        raise ValueError("metric pattern did not match command output")
    raw = matches[-1]
    if isinstance(raw, tuple):
        raw = next((part for part in raw if part), "")
    value = float(raw)
    return abs(value) if parser.get("absolute", False) else value


def run_once(manifest: dict[str, Any], repetition: int) -> dict[str, Any]:
    command = [str(item) for item in manifest["command"]]
    cwd = Path(manifest.get("working_directory", "."))
    parser = manifest["parser"]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True,
            timeout=int(manifest["timeout_seconds"]),
            env={**os.environ, "PQC_STAGE11_REPETITION": str(repetition)},
        )
        duration = time.monotonic() - started
        combined = proc.stdout + "\n" + proc.stderr
        digest = hashlib.sha256(combined.encode()).hexdigest()
        result: dict[str, Any] = {
            "repetition": repetition, "command": command,
            "command_display": shlex.join(command), "return_code": proc.returncode,
            "duration_seconds": duration, "output_sha256": digest,
            "stdout": proc.stdout, "stderr": proc.stderr,
            "status": "command-failed" if proc.returncode else "ok",
        }
        skip_pattern = parser.get("skip_pattern")
        if skip_pattern and re.search(skip_pattern, combined,
                                      flags=re.IGNORECASE | re.MULTILINE):
            result["status"] = "skipped"
            return result
        if proc.returncode == 0 and parser.get("type") == "regex":
            try:
                result["metric"] = parse_metric(combined, parser)
            except ValueError as error:
                result["status"] = "parse-failed"
                result["error"] = str(error)
        elif proc.returncode == 0 and parser.get("type") == "exit_status":
            result["metric"] = 0.0
        return result
    except subprocess.TimeoutExpired as error:
        return {"repetition": repetition, "command": command,
                "command_display": shlex.join(command),
                "duration_seconds": time.monotonic() - started,
                "status": "timeout", "error": str(error)}
    except OSError as error:
        return {"repetition": repetition, "command": command,
                "command_display": shlex.join(command),
                "duration_seconds": time.monotonic() - started,
                "status": "launch-failed", "error": str(error)}


def summarize(manifest: dict[str, Any], runs: list[dict[str, Any]]) -> dict[str, Any]:
    values = [float(run["metric"]) for run in runs if run.get("status") == "ok"]
    minimum_success = int(manifest["policy"]["minimum_successful_repetitions"])
    policy = manifest["policy"]
    if len(values) < minimum_success:
        decision = "inconclusive"
    elif "maximum" in policy and max(values) > float(policy["maximum"]):
        decision = "fail"
    elif "minimum" in policy and min(values) < float(policy["minimum"]):
        decision = "fail"
    else:
        decision = "pass"
    stats: dict[str, Any] = {
        "successful_repetitions": len(values), "requested_repetitions": len(runs),
        "skipped_repetitions": sum(run.get("status") == "skipped" for run in runs),
        "decision": decision,
    }
    if "maximum" in policy:
        stats["policy_maximum"] = float(policy["maximum"])
    if "minimum" in policy:
        stats["policy_minimum"] = float(policy["minimum"])
    if values:
        stats.update({"minimum": min(values), "maximum": max(values),
                      "mean": statistics.fmean(values),
                      "median": statistics.median(values),
                      "population_stddev": statistics.pstdev(values)})
    return stats


def markdown_report(report: dict[str, Any]) -> str:
    lines = ["# Stage 11 Side-Channel Evaluation Report", "",
             f"Generated: `{report['environment']['captured_at_utc']}`", "",
             "This report records statistical regression evidence. It is not a proof of constant-time execution.",
             "", "## Environment", "",
             f"- Platform: `{report['environment']['platform']}`",
             f"- Machine: `{report['environment']['machine']}`",
             f"- Rust: `{report['environment']['rustc']}`",
             f"- Commit: `{report['environment']['git_commit']}`", "",
             "## Experiments", "",
             "| Experiment | Decision | Successful | Skipped | Observed range | Policy |",
             "|---|---:|---:|---:|---:|---:|"]
    for item in report["experiments"]:
        s = item["summary"]
        observed = "n/a" if "minimum" not in s else f"{s['minimum']:.4g}..{s['maximum']:.4g}"
        policy_parts=[]
        if "policy_minimum" in s: policy_parts.append(f">={s['policy_minimum']}")
        if "policy_maximum" in s: policy_parts.append(f"<={s['policy_maximum']}")
        lines.append(f"| `{item['id']}` | **{s['decision']}** | "
                     f"{s['successful_repetitions']}/{s['requested_repetitions']} | "
                     f"{s['skipped_repetitions']} | {observed} | {'; '.join(policy_parts) or 'exit=0'} |")
    lines.extend(["", "## Interpretation", "",
                  "A failure indicates a threshold crossing that requires investigation. "
                  "An inconclusive result indicates missing harnesses or insufficient successful measurements.", ""])
    return "\n".join(lines)


def discover(directory: Path) -> list[tuple[Path, dict[str, Any]]]:
    manifests=[]
    for path in sorted(directory.glob("*.json")):
        manifest=load_json(path); validate_manifest(path, manifest); manifests.append((path,manifest))
    return manifests


def main() -> int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--experiments", type=Path, default=Path("sidechannel/experiments"))
    parser.add_argument("--output", type=Path, default=Path("target/stage11"))
    parser.add_argument("--include-disabled", action="store_true")
    parser.add_argument("--list", action="store_true")
    args=parser.parse_args()
    manifests=discover(args.experiments)
    if args.list:
        for path, manifest in manifests:
            state="enabled" if manifest["enabled"] else "disabled"
            print(f"{manifest['id']}: {state} ({path})")
        return 0
    selected=[pair for pair in manifests if pair[1]["enabled"] or args.include_disabled]
    args.output.mkdir(parents=True, exist_ok=True)
    report={"schema_version":SCHEMA_VERSION,"environment":environment_record(),"experiments":[]}
    for path, manifest in selected:
        print(f"running {manifest['id']} ({manifest['repetitions']} repetitions)")
        runs=[run_once(manifest,i) for i in range(1,int(manifest["repetitions"])+1)]
        item={"id":manifest["id"],"manifest":str(path),"description":manifest["description"],
              "tags":manifest.get("tags",[]),"runs":runs,"summary":summarize(manifest,runs)}
        report["experiments"].append(item)
        print(f"  decision: {item['summary']['decision']}")
    json_path=args.output/"report.json"; md_path=args.output/"report.md"
    json_path.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    md_path.write_text(markdown_report(report),encoding="utf-8")
    decisions=[item["summary"]["decision"] for item in report["experiments"]]
    print(f"JSON report: {json_path}"); print(f"Markdown report: {md_path}")
    if "fail" in decisions: return 1
    if "inconclusive" in decisions: return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
