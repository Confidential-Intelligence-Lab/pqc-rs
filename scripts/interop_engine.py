#!/usr/bin/env python3
"""A2.1 provider-driven interoperability engine for pqc-rfc9958-rs."""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import os
import pathlib
import subprocess
import sys
import tomllib
from dataclasses import dataclass, asdict
from typing import Any

ENGINE_SCHEMA_VERSION = 1
SUPPORTED_MANIFEST_SCHEMA_VERSIONS = {1}
SUPPORTED_VECTOR_SCHEMA_VERSIONS = {1}
HEX_KEYS = {
    "seed", "message", "context", "digest", "public_key", "secret_key", "encapsulation_key",
    "decapsulation_key", "ciphertext", "shared_secret", "signature", "randomness", "coins", "mu"
}

@dataclass
class Finding:
    severity: str
    code: str
    message: str
    provider: str | None = None
    suite: str | None = None
    vector_id: str | None = None


def canonical(value: Any, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {k: canonical(value[k], k) for k in sorted(value)}
    if isinstance(value, list):
        return [canonical(v, key) for v in value]
    if isinstance(value, str) and (key in HEX_KEYS or key is not None and key.endswith("_hex")):
        compact = "".join(value.split()).lower()
        if compact.startswith("0x"):
            compact = compact[2:]
        if compact and all(c in "0123456789abcdef" for c in compact) and len(compact) % 2 == 0:
            return compact
    return value


def run_provider(command: list[str], request: dict[str, Any], root: pathlib.Path, timeout: int) -> tuple[dict[str, Any] | None, str | None]:
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "PQC_INTEROP_PROTOCOL_VERSION": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if completed.returncode != 0:
        return None, f"exit={completed.returncode}; stderr={completed.stderr.strip()}"
    try:
        return json.loads(completed.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON response: {exc}; stdout={completed.stdout[:300]!r}"


def supports(capabilities: list[dict[str, Any]], vector: dict[str, Any]) -> bool:
    for item in capabilities:
        if item.get("algorithm") != vector.get("algorithm"):
            continue
        if vector.get("parameter_set") not in item.get("parameter_sets", []):
            continue
        if vector.get("operation") not in item.get("operations", []):
            continue
        return True
    return False


def load_vectors(root: pathlib.Path, patterns: list[str], findings: list[Finding], suite_id: str) -> list[dict[str, Any]]:
    paths: list[pathlib.Path] = []
    for pattern in patterns:
        paths.extend(pathlib.Path(p) for p in glob.glob(str(root / pattern), recursive=True))
    vectors: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(set(paths)):
        try:
            value = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(Finding("error", "VECTOR_PARSE_ERROR", f"{path}: {exc}", suite=suite_id))
            continue
        vector_id = str(value.get("vector_id", ""))
        required = {"schema_version", "vector_id", "suite", "algorithm", "parameter_set", "operation", "inputs", "expected"}
        missing = sorted(required - value.keys())
        if missing:
            findings.append(Finding("error", "VECTOR_MISSING_FIELDS", f"{path}: missing {', '.join(missing)}", suite=suite_id, vector_id=vector_id or None))
            continue
        if value["schema_version"] not in SUPPORTED_VECTOR_SCHEMA_VERSIONS:
            findings.append(Finding("error", "UNSUPPORTED_VECTOR_SCHEMA", f"{path}: schema_version={value['schema_version']}", suite=suite_id, vector_id=vector_id))
            continue
        if value["suite"] != suite_id:
            findings.append(Finding("error", "VECTOR_SUITE_MISMATCH", f"{path}: declares suite {value['suite']}", suite=suite_id, vector_id=vector_id))
        if vector_id in seen:
            findings.append(Finding("error", "DUPLICATE_VECTOR_ID", vector_id, suite=suite_id, vector_id=vector_id))
        seen.add(vector_id)
        vectors.append(value)
    if not vectors:
        findings.append(Finding("error", "EMPTY_SUITE", "No vectors resolved", suite=suite_id))
    return vectors


def write_reports(output: pathlib.Path, report: dict[str, Any]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (output / "findings.json").write_text(json.dumps(report["findings"], indent=2, sort_keys=True) + "\n")
    lines = [
        "# Interoperability Report", "",
        f"- Decision: **{report['decision']}**",
        f"- Strict mode: `{report['strict']}`",
        f"- Executed: {report['summary']['executed']}",
        f"- Passed: {report['summary']['passed']}",
        f"- Failed: {report['summary']['failed']}",
        f"- Skipped: {report['summary']['skipped']}", "",
        "## Providers", "",
        "| Provider | Enabled | Required | Available | Executed | Passed | Failed | Decision |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for p in report["providers"]:
        lines.append(f"| `{p['id']}` | {p['enabled']} | {p['required']} | {p['available']} | {p['executed']} | {p['passed']} | {p['failed']} | **{p['decision']}** |")
    lines += ["", "## Results", "", "| Provider | Suite | Vector | Algorithm | Parameter set | Operation | Decision |", "|---|---|---|---|---|---|---|"]
    for r in report["results"]:
        lines.append(f"| `{r['provider']}` | `{r['suite']}` | `{r['vector_id']}` | `{r['algorithm']}` | `{r['parameter_set']}` | `{r['operation']}` | **{r['decision']}** |")
    lines += ["", "## Findings", ""]
    if report["findings"]:
        for f in report["findings"]:
            lines.append(f"- **{f['severity']} {f['code']}**: {f['message']}")
    else:
        lines.append("No findings.")
    lines += ["", "## Claim boundary", "", "A passing framework report confirms protocol execution and result consistency for the enabled providers and loaded vectors only. It does not by itself establish standards conformance, independent validation, or interoperability with disabled providers.", ""]
    (output / "report.md").write_text("\n".join(lines))


def report(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.root).resolve()
    manifest_path = (root / args.manifest).resolve()
    findings: list[Finding] = []
    try:
        with manifest_path.open("rb") as handle:
            manifest = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"error: cannot load {manifest_path}: {exc}", file=sys.stderr)
        return 2
    meta = manifest.get("interop", {})
    if meta.get("schema_version") not in SUPPORTED_MANIFEST_SCHEMA_VERSIONS:
        findings.append(Finding("error", "UNSUPPORTED_MANIFEST_SCHEMA", str(meta.get("schema_version"))))
    timeout = int(meta.get("default_timeout_seconds", 30))
    output = (root / (args.output or meta.get("output", "target/interop"))).resolve()
    provider_filter = set(args.provider or [])
    suite_filter = set(args.suite or [])
    providers_cfg = {str(p.get("id")): p for p in manifest.get("provider", [])}
    suites_cfg = {str(s.get("id")): s for s in manifest.get("suite", [])}
    if len(providers_cfg) != len(manifest.get("provider", [])):
        findings.append(Finding("error", "DUPLICATE_PROVIDER_ID", "Provider IDs must be unique"))
    if len(suites_cfg) != len(manifest.get("suite", [])):
        findings.append(Finding("error", "DUPLICATE_SUITE_ID", "Suite IDs must be unique"))

    provider_reports: list[dict[str, Any]] = []
    capabilities_by_provider: dict[str, list[dict[str, Any]]] = {}
    for provider_id, cfg in providers_cfg.items():
        if provider_filter and provider_id not in provider_filter:
            continue
        enabled = bool(cfg.get("enabled", False))
        required = bool(cfg.get("required", False))
        pr = {"id": provider_id, "title": cfg.get("title", provider_id), "enabled": enabled, "required": required, "available": False, "executed": 0, "passed": 0, "failed": 0, "skipped": 0, "decision": "skip"}
        if not enabled:
            provider_reports.append(pr)
            continue
        command = [str(x) for x in cfg.get("command", [])]
        if not command:
            findings.append(Finding("error", "MISSING_PROVIDER_COMMAND", "Enabled provider has no command", provider=provider_id))
            pr["decision"] = "fail"
            provider_reports.append(pr)
            continue
        response, error = run_provider(command, {"protocol_version": 1, "action": "capabilities"}, root, timeout)
        if error or not response or not response.get("ok"):
            findings.append(Finding("error" if required or args.strict else "warning", "PROVIDER_UNAVAILABLE", error or str(response), provider=provider_id))
            pr["decision"] = "fail" if required or args.strict else "skip"
            provider_reports.append(pr)
            continue
        pr["available"] = True
        pr["decision"] = "pass"
        capabilities_by_provider[provider_id] = list(response.get("capabilities", []))
        provider_reports.append(pr)

    provider_report_map = {p["id"]: p for p in provider_reports}
    results: list[dict[str, Any]] = []
    seen_vector_ids: set[str] = set()
    for suite_id, cfg in suites_cfg.items():
        if suite_filter and suite_id not in suite_filter:
            continue
        vectors = load_vectors(root, [str(v) for v in cfg.get("vectors", [])], findings, suite_id)
        for vector in vectors:
            if vector["vector_id"] in seen_vector_ids:
                findings.append(Finding("error", "GLOBAL_DUPLICATE_VECTOR_ID", vector["vector_id"], suite=suite_id, vector_id=vector["vector_id"]))
            seen_vector_ids.add(vector["vector_id"])
        for provider_id in cfg.get("providers", []):
            provider_id = str(provider_id)
            if provider_filter and provider_id not in provider_filter:
                continue
            if provider_id not in providers_cfg:
                findings.append(Finding("error", "UNKNOWN_SUITE_PROVIDER", provider_id, provider=provider_id, suite=suite_id))
                continue
            pr = provider_report_map.get(provider_id)
            if pr is None or not pr["enabled"] or not pr["available"]:
                if pr is not None:
                    pr["skipped"] += len(vectors)
                continue
            command = [str(x) for x in providers_cfg[provider_id]["command"]]
            for vector in vectors:
                base = {"provider": provider_id, "suite": suite_id, "vector_id": vector["vector_id"], "algorithm": vector["algorithm"], "parameter_set": vector["parameter_set"], "operation": vector["operation"]}
                if not supports(capabilities_by_provider[provider_id], vector):
                    pr["skipped"] += 1
                    results.append({**base, "decision": "skip", "reason": "unsupported capability"})
                    continue
                pr["executed"] += 1
                response, error = run_provider(command, {"protocol_version": 1, "action": "execute", "case": vector}, root, timeout)
                if error or not response or not response.get("ok"):
                    pr["failed"] += 1
                    pr["decision"] = "fail"
                    message = error or str(response.get("error") if response else response)
                    findings.append(Finding("error", "PROVIDER_EXECUTION_FAILED", message, provider=provider_id, suite=suite_id, vector_id=vector["vector_id"]))
                    results.append({**base, "decision": "fail", "reason": message})
                    continue
                expected = canonical(vector["expected"])
                actual = canonical(response.get("outputs", {}))
                if actual != expected:
                    pr["failed"] += 1
                    pr["decision"] = "fail"
                    findings.append(Finding("error", "OUTPUT_MISMATCH", f"expected={expected!r}; actual={actual!r}", provider=provider_id, suite=suite_id, vector_id=vector["vector_id"]))
                    results.append({**base, "decision": "fail", "expected": expected, "actual": actual})
                else:
                    pr["passed"] += 1
                    results.append({**base, "decision": "pass"})

    enabled_available = [p for p in provider_reports if p["enabled"] and p["available"]]
    if not enabled_available:
        findings.append(Finding("error", "NO_AVAILABLE_PROVIDER", "No enabled provider completed capability negotiation"))
    if sum(p["executed"] for p in provider_reports) == 0:
        findings.append(Finding("error", "NO_EXECUTED_CASES", "No interoperability cases executed"))
    failed = sum(p["failed"] for p in provider_reports)
    errors = sum(1 for f in findings if f.severity == "error")
    decision = "fail" if failed or errors else "pass"
    summary = {
        "providers": len(provider_reports),
        "enabled_providers": sum(1 for p in provider_reports if p["enabled"]),
        "available_providers": sum(1 for p in provider_reports if p["available"]),
        "vectors": len(seen_vector_ids),
        "executed": sum(p["executed"] for p in provider_reports),
        "passed": sum(p["passed"] for p in provider_reports),
        "failed": failed,
        "skipped": sum(p["skipped"] for p in provider_reports),
        "errors": errors,
        "warnings": sum(1 for f in findings if f.severity == "warning"),
    }
    payload = {
        "schema_version": ENGINE_SCHEMA_VERSION,
        "project": str(meta.get("project", "pqc-rfc9958-rs")),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "decision": decision,
        "strict": bool(args.strict),
        "manifest": str(manifest_path.relative_to(root)),
        "summary": summary,
        "providers": provider_reports,
        "results": results,
        "findings": [asdict(f) for f in findings],
    }
    write_reports(output, payload)
    print(f"decision={decision}")
    print(f"providers={summary['providers']}")
    print(f"executed={summary['executed']}")
    print(f"report={output / 'report.md'}")
    return 0 if decision == "pass" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("report")
    run.add_argument("--root", default=".")
    run.add_argument("--manifest", default="interop/manifest.toml")
    run.add_argument("--output")
    run.add_argument("--provider", action="append")
    run.add_argument("--suite", action="append")
    run.add_argument("--strict", action="store_true")
    return parser


if __name__ == "__main__":
    ns = build_parser().parse_args()
    raise SystemExit(report(ns))
