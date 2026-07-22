#!/usr/bin/env python3
"""Classify Stage 10B-5 audit-wrapper machine code on ARM64 and x86-64."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ADDRESS_HEADER = re.compile(r"^\s*[0-9a-fA-F]+\s+<(.+)>:$")
INSTRUCTION = re.compile(
    r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)*"
    r"([A-Za-z.][A-Za-z0-9.]*)\s*(.*)$"
)
LOCAL_LABEL = re.compile(r"^(?:\.?L(?:BB|tmp|func|CPI)|\.L)")

ARM_CONDITIONAL_BRANCHES = {
    "b.eq",
    "b.ne",
    "b.lt",
    "b.le",
    "b.gt",
    "b.ge",
    "b.hi",
    "b.hs",
    "b.lo",
    "b.ls",
    "b.mi",
    "b.pl",
    "b.vs",
    "b.vc",
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: root must be an object")
    return value


def header_symbol(line: str) -> str | None:
    match = ADDRESS_HEADER.match(line)
    if match:
        return match.group(1)

    stripped = line.strip()
    if not stripped.endswith(":") or INSTRUCTION.match(line):
        return None
    symbol = stripped[:-1]
    if not symbol or LOCAL_LABEL.match(symbol):
        return None
    return symbol


def parse_functions(text: str) -> dict[str, list[str]]:
    functions: dict[str, list[str]] = {}
    current: str | None = None

    for line in text.splitlines():
        symbol = header_symbol(line)
        if symbol is not None:
            current = symbol
            functions.setdefault(symbol, [])
            continue
        if current is not None:
            functions[current].append(line)

    return functions


def instruction(line: str) -> tuple[str, str] | None:
    match = INSTRUCTION.match(line)
    if not match:
        return None
    return match.group(1).lower(), match.group(2).strip()


def is_conditional_branch(mnemonic: str) -> bool:
    if mnemonic in ARM_CONDITIONAL_BRANCHES:
        return True
    if mnemonic in {"loop", "loope", "loopne", "jcxz", "jecxz", "jrcxz"}:
        return True
    return mnemonic.startswith("j") and not mnemonic.startswith("jmp")


def is_division(mnemonic: str) -> bool:
    return bool(re.fullmatch(r"(?:i?div[a-z0-9]*|[su]div)", mnemonic))


def is_store(mnemonic: str, operands: str) -> bool:
    if mnemonic.startswith(("str", "stp", "stur")):
        return True
    if mnemonic.startswith("stos") or mnemonic in {"movnti", "movntdq", "movntps"}:
        return True
    if not mnemonic.startswith("mov"):
        return False

    parts = [part.strip() for part in operands.split(",")]
    if len(parts) < 2:
        return False

    # LLVM uses AT&T syntax by default on x86 (memory destination last), while
    # some installations may emit Intel syntax (memory destination first).
    first, last = parts[0], parts[-1]
    return ("[" in first and "]" in first) or ("(" in last and ")" in last)


def classify(lines: list[str]) -> dict[str, list[str]]:
    result = {
        "conditional_branches": [],
        "divisions": [],
        "stores": [],
        "instructions": [],
    }
    for line in lines:
        parsed = instruction(line)
        if parsed is None:
            continue
        mnemonic, operands = parsed
        rendered = line.strip()
        result["instructions"].append(rendered)
        if is_conditional_branch(mnemonic):
            result["conditional_branches"].append(rendered)
        if is_division(mnemonic):
            result["divisions"].append(rendered)
        if is_store(mnemonic, operands):
            result["stores"].append(rendered)
    return result


def matching_functions(
    functions: dict[str, list[str]],
    fragment: str,
) -> dict[str, list[str]]:
    return {
        symbol: lines
        for symbol, lines in functions.items()
        if fragment in symbol
    }


def combine_classification(
    functions: dict[str, list[str]],
) -> dict[str, list[str]]:
    combined = {
        "conditional_branches": [],
        "divisions": [],
        "stores": [],
        "instructions": [],
    }
    for lines in functions.values():
        classified = classify(lines)
        for key in combined:
            combined[key].extend(classified[key])
    return combined


def analyze_binary(
    binary_policy: dict[str, Any],
    objdump: Path,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    functions = parse_functions(objdump.read_text(encoding="utf-8", errors="replace"))
    findings: list[dict[str, str]] = []
    wrappers = []

    for wrapper_policy in binary_policy["wrappers"]:
        name = wrapper_policy["name"]
        matches = matching_functions(functions, name)
        classified = combine_classification(matches)
        status = "pass"

        if not matches:
            status = "fail"
            findings.append({
                "binary": binary_policy["name"],
                "wrapper": name,
                "finding": "required wrapper symbol was not recovered",
            })
        if classified["divisions"]:
            status = "fail"
            findings.append({
                "binary": binary_policy["name"],
                "wrapper": name,
                "finding": "division instruction in audited wrapper",
            })
        if (
            wrapper_policy["control_policy"] == "branchless"
            and classified["conditional_branches"]
        ):
            status = "fail"
            findings.append({
                "binary": binary_policy["name"],
                "wrapper": name,
                "finding": "conditional branch in branchless wrapper",
            })

        wrappers.append({
            "name": name,
            "control_policy": wrapper_policy["control_policy"],
            "status": status,
            "matched_symbols": sorted(matches),
            "instruction_count": len(classified["instructions"]),
            "conditional_branches": classified["conditional_branches"],
            "divisions": classified["divisions"],
            "stores": classified["stores"],
        })

    zeroization = None
    if binary_policy.get("require_zeroization_store", False):
        related = {
            symbol: lines
            for symbol, lines in functions.items()
            if "zeroize" in symbol.lower()
            or ("drop_in_place" in symbol and "SecretBytes" in symbol)
        }
        classified = combine_classification(related)
        zeroization = {
            "status": "pass" if classified["stores"] else "fail",
            "matched_symbols": sorted(related),
            "stores": classified["stores"],
        }
        if not classified["stores"]:
            findings.append({
                "binary": binary_policy["name"],
                "wrapper": "zeroization-family",
                "finding": "no store instruction recovered from zeroization functions",
            })

    report = {
        "name": binary_policy["name"],
        "objdump": str(objdump),
        "function_count": len(functions),
        "wrappers": wrappers,
        "zeroization": zeroization,
        "decision": "fail" if findings else "pass",
    }
    return report, findings


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Stage 10B-5 machine-code report",
        "",
        f"Target: `{report['target_id']}`",
        "",
        f"Decision: **{report['decision'].upper()}**",
        "",
        "Conditional branches are forbidden only in wrappers whose versioned "
        "policy is `branchless`. Public-length control flow and zeroization-loop "
        "control are inventoried but are not treated as secret-dependent.",
        "",
    ]
    for binary in report["binaries"]:
        lines.extend([f"## `{binary['name']}`", ""])
        for wrapper in binary["wrappers"]:
            lines.append(
                f"- `{wrapper['name']}`: **{wrapper['status']}**; "
                f"policy={wrapper['control_policy']}; "
                f"instructions={wrapper['instruction_count']}; "
                f"branches={len(wrapper['conditional_branches'])}; "
                f"divisions={len(wrapper['divisions'])}"
            )
        if binary["zeroization"] is not None:
            lines.append(
                f"- zeroization stores: **{binary['zeroization']['status']}** "
                f"({len(binary['zeroization']['stores'])} candidates)"
            )
        lines.append("")
    lines.extend(["## Findings", ""])
    if report["findings"]:
        for finding in report["findings"]:
            lines.append(
                f"- `{finding['binary']}::{finding['wrapper']}`: "
                f"{finding['finding']}"
            )
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def self_test() -> int:
    sample = """
0000000000001000 <example::audit_branchless>:
  1000: movq %rsi, (%rdi)
  1004: retq
0000000000001010 <example::audit_branched>:
  1010: cbz x0, 0x1020
  1014: udiv x0, x1, x2
"""
    functions = parse_functions(sample)
    first = combine_classification(matching_functions(functions, "audit_branchless"))
    second = combine_classification(matching_functions(functions, "audit_branched"))
    if len(functions) != 2:
        raise AssertionError("function parser self-test failed")
    if len(first["stores"]) != 1 or first["conditional_branches"]:
        raise AssertionError("x86 store classifier self-test failed")
    if len(second["conditional_branches"]) != 1 or len(second["divisions"]) != 1:
        raise AssertionError("ARM classifier self-test failed")
    print("Stage 10B-5 machine-code analyzer self-test passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--target-id")
    parser.add_argument("--objdump-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not all((args.policy, args.target_id, args.objdump_dir, args.output)):
        parser.error("--policy, --target-id, --objdump-dir, and --output are required")

    policy = load_json(args.policy)
    binaries = []
    findings = []
    for binary_policy in policy["binaries"]:
        objdump = args.objdump_dir / f"{binary_policy['name']}.objdump.txt"
        if not objdump.is_file():
            findings.append({
                "binary": binary_policy["name"],
                "wrapper": "all",
                "finding": f"missing objdump file: {objdump}",
            })
            binaries.append({
                "name": binary_policy["name"],
                "objdump": str(objdump),
                "function_count": 0,
                "wrappers": [],
                "zeroization": None,
                "decision": "fail",
            })
            continue
        binary_report, binary_findings = analyze_binary(binary_policy, objdump)
        binaries.append(binary_report)
        findings.extend(binary_findings)

    expected_wrapper_count = sum(
        len(binary_policy["wrappers"])
        for binary_policy in policy["binaries"]
    )
    recovered_wrapper_count = sum(
        bool(wrapper["matched_symbols"])
        for binary in binaries
        for wrapper in binary["wrappers"]
    )

    report = {
        "schema_version": 1,
        "target_id": args.target_id,
        "binaries": binaries,
        "findings": findings,
        "generated_code_decision": (
            "pass" if recovered_wrapper_count == expected_wrapper_count else "fail"
        ),
        "secret_dependency_decision": "fail" if findings else "pass",
        "decision": "fail" if findings else "pass",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.output.with_suffix(".md").write_text(markdown_report(report), encoding="utf-8")
    print(f"machine-code decision={report['decision']}")
    print(args.output)
    return 0 if report["decision"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
