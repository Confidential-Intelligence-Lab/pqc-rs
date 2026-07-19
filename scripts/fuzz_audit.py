#!/usr/bin/env python3
"""Generate and validate the B1.3.4 structured fuzzing artifacts."""

from __future__ import annotations

import argparse
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "compliance/fuzz-policy.toml"
AUDIT = ROOT / "docs/security/STRUCTURED_FUZZING.md"
REGISTER = ROOT / "docs/security/FUZZ_TARGET_REGISTER.md"
FUZZ_MANIFEST = ROOT / "fuzz/Cargo.toml"
SMOKE_SCRIPT = ROOT / "scripts/run-fuzz-smoke.sh"


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
    seen_ids: set[str] = set()
    seen_names: set[str] = set()

    if meta.get("schema_version") != 1:
        findings.append(Finding("error", "metadata", "schema_version must be 1"))
    if not targets:
        findings.append(Finding("error", "policy", "at least one fuzz target is required"))

    manifest_text = FUZZ_MANIFEST.read_text(encoding="utf-8") if FUZZ_MANIFEST.is_file() else ""
    smoke_text = SMOKE_SCRIPT.read_text(encoding="utf-8") if SMOKE_SCRIPT.is_file() else ""

    for target in targets:
        ident = target.get("id", "<missing>")
        name = target.get("name", "<missing>")
        if ident in seen_ids:
            findings.append(Finding("error", ident, "duplicate target id"))
        if name in seen_names:
            findings.append(Finding("error", ident, f"duplicate target name: {name}"))
        seen_ids.add(ident)
        seen_names.add(name)

        if target.get("status") not in statuses:
            findings.append(Finding("error", ident, f"invalid status: {target.get('status')}"))
        if target.get("class") not in classes:
            findings.append(Finding("error", ident, f"invalid class: {target.get('class')}"))
        if not target.get("properties"):
            findings.append(Finding("error", ident, "at least one fuzz property is required"))

        path = ROOT / target.get("path", "")
        if not path.is_file():
            findings.append(Finding("error", ident, f"missing target source: {target.get('path')}"))
        if f'name = "{name}"' not in manifest_text:
            findings.append(Finding("error", ident, "target is absent from fuzz/Cargo.toml"))
        if target.get("status") == "active" and name not in smoke_text:
            findings.append(Finding("error", ident, "active target is absent from smoke runner"))

        corpus = ROOT / target.get("seed_corpus", "")
        if not corpus.is_dir():
            findings.append(Finding("error", ident, f"missing seed corpus directory: {target.get('seed_corpus')}"))
        dictionary = target.get("dictionary")
        if dictionary and not (ROOT / dictionary).is_file():
            findings.append(Finding("error", ident, f"missing dictionary: {dictionary}"))

    workflow = ROOT / ".github/workflows/fuzz-smoke.yml"
    if not workflow.is_file():
        findings.append(Finding("error", "ci", "missing fuzz smoke workflow"))
    return findings


def joined(values: list[str]) -> str:
    return "; ".join(values) if values else "None recorded"


def render_audit(data: dict, findings: list[Finding]) -> str:
    targets = data["target"]
    active = [target for target in targets if target["status"] == "active"]
    errors = sum(f.severity == "error" for f in findings)
    classes: dict[str, int] = {}
    for target in active:
        classes[target["class"]] = classes.get(target["class"], 0) + 1

    lines = [
        "# Structured Fuzzing",
        "",
        "> Generated from `compliance/fuzz-policy.toml` by `scripts/fuzz_audit.py`. Do not edit manually.",
        "",
        "## Scope and claim",
        "",
        f"Milestone: **{data['metadata']['review_boundary']}**.",
        "",
        f"Claim boundary: **{data['metadata']['claim']}**.",
        "",
        "The fuzzing program targets malformed encodings, parser robustness, protocol state transitions, cryptographic API boundaries, and arithmetic invariants. Every active target must be declared in the cargo-fuzz manifest, included in bounded CI smoke execution, and associated with a persistent seed-corpus directory.",
        "",
        "## Decision",
        "",
        f"**{'PASS' if errors == 0 else 'FAIL'}** — {len(active)} active targets; {errors} blocking findings.",
        "",
        "## Coverage summary",
        "",
        "| Dimension | Count |",
        "|---|---:|",
        f"| Active targets | {len(active)} |",
        f"| CI smoke duration per target | {data['metadata']['smoke_seconds']} seconds |",
        f"| Recommended campaign duration per target | {data['metadata']['campaign_seconds']} seconds |",
    ]
    for name, count in sorted(classes.items()):
        lines.append(f"| `{name}` targets | {count} |")

    lines += [
        "",
        "## Execution profiles",
        "",
        "### Pull-request smoke",
        "",
        "```bash",
        "cargo xtask fuzz-audit --check",
        "FUZZ_SECONDS=30 ./scripts/run-fuzz-smoke.sh",
        "```",
        "",
        "### Focused campaign",
        "",
        "```bash",
        "FUZZ_SECONDS=3600 FUZZ_TARGETS=ml_kem_decapsulation ./scripts/run-fuzz-smoke.sh",
        "```",
        "",
        "Crashes and timeouts are written under `fuzz/artifacts/<target>/`. Every confirmed defect must receive a deterministic regression test before the artifact is removed. Useful non-crashing inputs should be promoted into the corresponding `fuzz/corpus/<target>/` directory.",
        "",
        "## Target details",
        "",
    ]
    for target in targets:
        lines += [
            f"### {target['id']} — `{target['name']}`",
            "",
            f"- Class: `{target['class']}`",
            f"- Status: `{target['status']}`",
            f"- Components: {joined(target.get('components', []))}",
            f"- Properties: {joined(target.get('properties', []))}",
            f"- Seed corpus: `{target['seed_corpus']}`",
        ]
        if target.get("dictionary"):
            lines.append(f"- Dictionary: `{target['dictionary']}`")
        lines.append("")

    lines += [
        "## Limitations",
        "",
        "- Coverage-guided fuzzing does not prove memory safety, correctness, standards conformance, constant-time behavior, or cryptographic security.",
        "- Bounded CI runs are regression screens; meaningful assurance requires longer campaigns on supported release targets.",
        "- Harness assertions are part of the security contract and require review when APIs or protocol state semantics change.",
        "- Third-party dependencies retain their own fuzzing and assurance boundaries.",
        "",
        "## Release maintenance",
        "",
        "Run all targets for an extended campaign before a release candidate. Archive the toolchain, target triple, duration, corpus hash, and crash disposition in the release evidence bundle.",
        "",
    ]
    return "\n".join(lines)


def render_register(data: dict, findings: list[Finding]) -> str:
    lines = [
        "# Fuzz Target Register",
        "",
        "> Generated from `compliance/fuzz-policy.toml` by `scripts/fuzz_audit.py`. Do not edit manually.",
        "",
        "| ID | Target | Class | Status | Corpus | Dictionary |",
        "|---|---|---|---|---|---|",
    ]
    for target in data["target"]:
        dictionary = f"`{target['dictionary']}`" if target.get("dictionary") else "—"
        lines.append(
            f"| `{target['id']}` | `{target['name']}` | `{target['class']}` | `{target['status']}` | `{target['seed_corpus']}` | {dictionary} |"
        )
    lines += ["", "## Gate findings", ""]
    if findings:
        for finding in findings:
            lines.append(f"- **{finding.severity.upper()}** `{finding.target}`: {finding.message}")
    else:
        lines.append("No policy, harness, corpus, manifest, or CI findings.")
    lines.append("")
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
    ok = write_or_check(AUDIT, render_audit(data, findings), args.check)
    ok &= write_or_check(REGISTER, render_register(data, findings), args.check)

    errors = [finding for finding in findings if finding.severity == "error"]
    for finding in findings:
        stream = sys.stderr if finding.severity == "error" else sys.stdout
        print(f"{finding.severity}: {finding.target}: {finding.message}", file=stream)
    if errors or not ok:
        return 1
    print(f"B1.3.4 fuzz audit: pass ({len(data['target'])} classified targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
