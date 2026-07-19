#!/usr/bin/env python3
"""Generate and validate the B1.3.3 constant-time audit artifacts."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "compliance/constant-time-policy.toml"
AUDIT = ROOT / "docs/security/CONSTANT_TIME_AUDIT.md"
REGISTER = ROOT / "docs/security/SECRET_DEPENDENCY_REGISTER.md"


@dataclass(frozen=True)
class Finding:
    severity: str
    target: str
    message: str


def load_policy() -> dict:
    with POLICY.open("rb") as handle:
        return tomllib.load(handle)


def validate(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    meta = data.get("metadata", {})
    statuses = set(meta.get("allowed_statuses", []))
    classes = set(meta.get("allowed_classes", []))
    targets = data.get("target", [])
    seen: set[str] = set()

    if meta.get("schema_version") != 1:
        findings.append(Finding("error", "metadata", "schema_version must be 1"))
    if not targets:
        findings.append(Finding("error", "policy", "at least one target is required"))

    for target in targets:
        ident = target.get("id", "<missing>")
        if ident in seen:
            findings.append(Finding("error", ident, "duplicate target id"))
        seen.add(ident)
        if target.get("status") not in statuses:
            findings.append(Finding("error", ident, f"invalid status: {target.get('status')}"))
        if target.get("class") not in classes:
            findings.append(Finding("error", ident, f"invalid class: {target.get('class')}"))
        path = ROOT / target.get("path", "")
        if not path.is_file():
            findings.append(Finding("error", ident, f"missing source path: {target.get('path')}"))
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for symbol in target.get("symbols", []):
            if symbol not in text and target["component"] != "release toolchain":
                findings.append(Finding("error", ident, f"symbol not found in source: {symbol}"))
        for evidence in target.get("evidence", []):
            if not (ROOT / evidence).is_file():
                findings.append(Finding("error", ident, f"missing evidence: {evidence}"))
        if target.get("status") == "unresolved":
            findings.append(Finding("error", ident, "unresolved target blocks B1.3.3"))
        if target.get("class") == "algorithmic-variable-time" and not target.get("notes"):
            findings.append(Finding("error", ident, "variable-time target requires notes"))

    register = ROOT / "audit/stage9f4e/security-finding-register.md"
    if not register.is_file():
        findings.append(Finding("error", "evidence", "missing Stage 9F-4E finding register"))
    else:
        text = register.read_text(encoding="utf-8")
        match = re.search(r"Open findings:\s*(\d+)", text)
        if not match:
            findings.append(Finding("warning", "evidence", "finding register does not state open finding count"))
        elif int(match.group(1)) != 0:
            findings.append(Finding("error", "evidence", f"finding register has {match.group(1)} open findings"))

    return findings


def md_list(values: list[str]) -> str:
    return "; ".join(values) if values else "None recorded"


def render_audit(data: dict, findings: list[Finding]) -> str:
    targets = data["target"]
    statuses: dict[str, int] = {}
    classes: dict[str, int] = {}
    for target in targets:
        statuses[target["status"]] = statuses.get(target["status"], 0) + 1
        classes[target["class"]] = classes.get(target["class"], 0) + 1
    errors = sum(f.severity == "error" for f in findings)
    lines = [
        "# Constant-Time Audit",
        "",
        "> Generated from `compliance/constant-time-policy.toml` by `scripts/constant_time_audit.py`. Do not edit manually.",
        "",
        "## Scope and claim",
        "",
        f"Milestone: **{data['metadata']['review_boundary']}**.",
        "",
        f"Claim boundary: **{data['metadata']['claim']}**.",
        "",
        "This audit consolidates the repository's source review, timing screens, rejection-loop analysis, and generated-code evidence. It distinguishes fixed-schedule operations from public or algorithmically variable-time operations. A passing gate is not a mathematical proof and is not portable across unreviewed compilers or targets.",
        "",
        "## Decision",
        "",
        f"**{'PASS' if errors == 0 else 'FAIL'}** — {len(targets)} targets classified; {errors} blocking findings.",
        "",
        "## Summary",
        "",
        "| Dimension | Count |",
        "|---|---:|",
    ]
    for key, value in sorted(classes.items()):
        lines.append(f"| Class: `{key}` | {value} |")
    for key, value in sorted(statuses.items()):
        lines.append(f"| Status: `{key}` | {value} |")
    lines += ["", "## Target register", "", "| ID | Component | Class | Status | Primary path |", "|---|---|---|---|---|"]
    for target in targets:
        lines.append(f"| `{target['id']}` | {target['component']} | `{target['class']}` | `{target['status']}` | `{target['path']}` |")
    lines += ["", "## Detailed review", ""]
    for target in targets:
        lines += [
            f"### {target['id']} — {target['component']}",
            "",
            f"- Classification: `{target['class']}`",
            f"- Status: `{target['status']}`",
            f"- Symbols: {md_list([f'`{v}`' for v in target.get('symbols', [])])}",
            f"- Secret inputs: {md_list(target.get('secret_inputs', []))}",
            f"- Public inputs: {md_list(target.get('public_inputs', []))}",
            f"- Requirements: {md_list(target.get('requirements', []))}",
            f"- Validation: {md_list(target.get('validation', []))}",
            f"- Evidence: {md_list([f'`{v}`' for v in target.get('evidence', [])])}",
        ]
        if target.get("notes"):
            lines.append(f"- Notes: {target['notes']}")
        lines.append("")
    lines += [
        "## Limitations",
        "",
        "- Timing screens detect statistical differences; they do not prove absence of leakage.",
        "- Generated-code conclusions apply only to the recorded compiler, optimization profile, and target architecture.",
        "- ML-DSA signing and selected sampling routines retain documented algorithmic variable work.",
        "- Third-party cryptographic dependencies remain within their own assurance boundaries.",
        "- Formal verification and hardware leakage evaluation are outside B1.3.3.",
        "",
        "## Required release maintenance",
        "",
        "Re-run the source, timing, and generated-code reviews after cryptographic code changes, compiler upgrades, target changes, or changes to optimization flags. Any unresolved secret-dependent branch or memory access must be entered into the finding register and blocks a constant-time assurance claim.",
        "",
    ]
    return "\n".join(lines)


def render_register(data: dict, findings: list[Finding]) -> str:
    targets = data["target"]
    lines = [
        "# Secret-Dependency Register",
        "",
        "> Generated from `compliance/constant-time-policy.toml` by `scripts/constant_time_audit.py`. Do not edit manually.",
        "",
        "This register records the security classification of control-flow and memory-access dependencies. `constant-time-required` means secret-dependent control flow and addressing are prohibited. `public-variable-time` permits variation based only on public values. `algorithmic-variable-time` records intentional variable work that requires explicit exposure analysis.",
        "",
        "| Target | Secret-bearing data | Permitted dependency | Prohibited dependency | Disposition |",
        "|---|---|---|---|---|",
    ]
    for t in targets:
        secret = md_list(t.get("secret_inputs", []))
        if t["class"] == "constant-time-required":
            permitted = "Public parameters, fixed loop indices, implementation control"
        elif t["class"] == "public-variable-time":
            permitted = "Public input and public result"
        else:
            permitted = "Documented transcript/randomness-driven algorithmic work"
        prohibited = "Secret-dependent branch, loop bound, error path, allocation, or address"
        lines.append(f"| `{t['id']}` | {secret} | {permitted} | {prohibited} | `{t['status']}` |")
    lines += ["", "## Gate findings", ""]
    if not findings:
        lines.append("No policy or evidence findings.")
    else:
        for finding in findings:
            lines.append(f"- **{finding.severity.upper()}** `{finding.target}`: {finding.message}")
    lines += [
        "",
        "## Residual exposure",
        "",
        "ML-DSA signing and selected sampling paths are explicitly classified as algorithmically variable-time. Their acceptance is limited to the documented FIPS 204 behavior and existing timing analyses; it is not a claim that execution time is independent of all secret-bearing state. Hardened deployment profiles may require additional mitigations, isolation, or alternative implementations.",
        "",
    ]
    return "\n".join(lines)


def write_or_check(path: Path, content: str, check: bool) -> bool:
    if check:
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            print(f"drift: {path.relative_to(ROOT)}", file=sys.stderr)
            return False
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = load_policy()
    findings = validate(data)
    audit = render_audit(data, findings)
    register = render_register(data, findings)
    ok = write_or_check(AUDIT, audit, args.check)
    ok &= write_or_check(REGISTER, register, args.check)
    errors = [f for f in findings if f.severity == "error"]
    for finding in findings:
        stream = sys.stderr if finding.severity == "error" else sys.stdout
        print(f"{finding.severity}: {finding.target}: {finding.message}", file=stream)
    if errors or not ok:
        return 1
    print(f"B1.3.3 constant-time audit: pass ({len(data['target'])} classified targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
