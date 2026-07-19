#!/usr/bin/env python3
"""Generate and validate the B1.3.5 performance baseline artifacts."""
from __future__ import annotations
import argparse
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "compliance/performance-policy.toml"
BASELINE = ROOT / "docs/performance/PERFORMANCE_BASELINE.md"
REGISTER = ROOT / "docs/performance/BENCHMARK_REGISTER.md"
WORKFLOW = ROOT / ".github/workflows/benchmark-smoke.yml"
RUNNER = ROOT / "scripts/run-performance-baseline.sh"

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
    benches = data.get("benchmark", [])
    statuses = set(meta.get("allowed_statuses", []))
    classes = set(meta.get("allowed_classes", []))
    seen_ids: set[str] = set()
    active_benches: set[str] = set()
    if meta.get("schema_version") != 1:
        findings.append(Finding("error", "metadata", "schema_version must be 1"))
    if not benches:
        findings.append(Finding("error", "policy", "at least one benchmark is required"))
    if meta.get("regression_review_percent", 0) >= meta.get("regression_block_percent", 0):
        findings.append(Finding("error", "metadata", "review threshold must be below block threshold"))
    workflow_text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
    for bench in benches:
        ident = bench.get("id", "<missing>")
        if ident in seen_ids:
            findings.append(Finding("error", ident, "duplicate benchmark id"))
        seen_ids.add(ident)
        if bench.get("status") not in statuses:
            findings.append(Finding("error", ident, f"invalid status: {bench.get('status')}"))
        if bench.get("class") not in classes:
            findings.append(Finding("error", ident, f"invalid class: {bench.get('class')}"))
        if not bench.get("parameter_sets"):
            findings.append(Finding("error", ident, "parameter_sets must not be empty"))
        if not bench.get("metrics"):
            findings.append(Finding("error", ident, "metrics must not be empty"))
        source = ROOT / bench.get("source", "")
        if not source.is_file():
            findings.append(Finding("error", ident, f"missing benchmark source: {bench.get('source')}"))
        if bench.get("status") == "active":
            active_benches.add(bench.get("bench", ""))
    for name in sorted(active_benches):
        if f"--bench {name}" not in workflow_text:
            findings.append(Finding("error", name, "active benchmark absent from smoke workflow"))
    if not RUNNER.is_file():
        findings.append(Finding("error", "runner", "missing performance baseline runner"))
    return findings

def joined(values: list[str]) -> str:
    return "; ".join(values) if values else "None recorded"

def render_baseline(data: dict, findings: list[Finding]) -> str:
    meta = data["metadata"]
    active = [b for b in data["benchmark"] if b["status"] == "active"]
    errors = sum(f.severity == "error" for f in findings)
    lines = [
        "# Performance Baseline",
        "",
        "> Generated from `compliance/performance-policy.toml` by `scripts/performance_audit.py`. Do not edit manually.",
        "",
        "## Scope and claim",
        "",
        f"Milestone: **{meta['review_boundary']}**.",
        "",
        f"Claim boundary: **{meta['claim']}**.",
        "",
        "This baseline measures release-mode cryptographic operations using Criterion. It records machine and toolchain provenance separately from correctness gates. Results are comparable only when the benchmark source, feature set, toolchain, target triple, power policy, and host conditions are controlled.",
        "",
        "## Decision",
        "",
        f"**{'PASS' if errors == 0 else 'FAIL'}** — {len(active)} active benchmark groups; {errors} blocking findings.",
        "",
        "## Execution",
        "",
        "```bash",
        "cargo xtask performance-audit --check",
        "./scripts/run-performance-baseline.sh",
        "```",
        "",
        "The runner writes provenance to `target/performance-baseline/environment.txt` and Criterion output beneath `target/criterion/`.",
        "",
        "## Regression policy",
        "",
        f"A sustained median regression of **{meta['regression_review_percent']}% or more** requires investigation. A sustained regression of **{meta['regression_block_percent']}% or more** blocks release unless explicitly accepted with rationale. These thresholds apply only to controlled, like-for-like measurements and are not enforced in generic CI runners.",
        "",
        "ML-DSA signing is rejection-sampled and therefore naturally variable. Review its distribution and signing trace together with median latency; do not interpret one timing sample as a constant-time claim.",
        "",
        "## Required provenance",
        "",
        "- CPU model, architecture, core count, and frequency policy",
        "- operating system and kernel version",
        "- Rust and Cargo versions plus target triple",
        "- Git revision and dirty-tree status",
        "- build profile and enabled features",
        "- benchmark source revision, sample count, and Criterion confidence interval",
        "- thermal, power, virtualization, and background-load conditions",
        "",
        "## Coverage",
        "",
        "| ID | Benchmark | Class | Parameter sets | Metrics |",
        "|---|---|---|---|---|",
    ]
    for bench in active:
        lines.append(f"| `{bench['id']}` | `{bench['name']}` | `{bench['class']}` | {joined(bench['parameter_sets'])} | {joined(bench['metrics'])} |")
    lines += [
        "",
        "## Interpretation boundaries",
        "",
        "- Criterion measurements are not evidence of constant-time execution or cryptographic security.",
        "- CI smoke mode validates compilation and execution only; it does not establish stable performance numbers.",
        "- Cross-machine comparisons are invalid unless hardware, firmware, compiler, target features, and operating conditions are normalized.",
        "- Allocation and peak-memory measurements are not yet part of this baseline and remain future work.",
        "",
    ]
    return "\n".join(lines)

def render_register(data: dict, findings: list[Finding]) -> str:
    lines = [
        "# Benchmark Register",
        "",
        "> Generated from `compliance/performance-policy.toml` by `scripts/performance_audit.py`. Do not edit manually.",
        "",
        "| ID | Criterion group | Crate | Bench target | Status | Source |",
        "|---|---|---|---|---|---|",
    ]
    for bench in data["benchmark"]:
        lines.append(f"| `{bench['id']}` | `{bench['name']}` | `{bench['crate']}` | `{bench['bench']}` | `{bench['status']}` | `{bench['source']}` |")
    lines += ["", "## Gate findings", ""]
    if findings:
        for finding in findings:
            lines.append(f"- **{finding.severity.upper()}** `{finding.target}`: {finding.message}")
    else:
        lines.append("No policy, source, runner, or CI findings.")
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
    ok = write_or_check(BASELINE, render_baseline(data, findings), args.check)
    ok &= write_or_check(REGISTER, render_register(data, findings), args.check)
    errors = [f for f in findings if f.severity == "error"]
    for finding in findings:
        stream = sys.stderr if finding.severity == "error" else sys.stdout
        print(f"{finding.severity}: {finding.target}: {finding.message}", file=stream)
    if errors or not ok:
        return 1
    print(f"B1.3.5 performance audit: pass ({len(data['benchmark'])} classified benchmark groups)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
