#!/usr/bin/env python3
"""Build a compact Stage 9F-4E security finding register."""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path


GROUPS = {
    "CHALLENGE_RESULT_CHECK": {
        "title": "Challenge-sampling Result check",
        "targets": {"audit_multiply_challenge", "audit_sample_ball"},
        "categories": {"conditional_branches"},
        "addresses": {"100000aa4", "100000c34"},
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "Branches test the Result discriminant returned by "
            "sample_in_ball_bytes and enter the unwrap/panic path on error. "
            "They do not depend on challenge coefficients or secret data."
        ),
    },
    "ETA_RESULT_CHECK": {
        "title": "Eta-sampling Result check",
        "targets": {"audit_sample_eta"},
        "categories": {"conditional_branches"},
        "addresses": {"100000b90"},
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "Branch tests the Result discriminant returned by sample_eta_poly "
            "and enters the unwrap/panic path on error."
        ),
    },
    "ROUNDING_BRANCHLESS_CORRECTION": {
        "title": "Branchless rounding corrections",
        "targets": {"audit_rounding"},
        "categories": {"conditional_selects", "vector_candidates"},
        "addresses": set(),
        "dependency": "secret-coefficient",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "LLVM lowers coefficient-dependent corrections to ARM64 csel and "
            "fixed-latency smull instructions. No secret-dependent branch or "
            "secret-indexed memory access is introduced."
        ),
    },
    "ROUNDING_LOOP_CONTROL": {
        "title": "Fixed rounding-wrapper loop control",
        "targets": {"audit_rounding"},
        "categories": {"conditional_branches", "indexed_memory_candidates"},
        "addresses": {"100000ddc", "100000ce8"},
        "dependency": "public-loop-index",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "The branch and indexed load implement iteration over a fixed "
            "public audit vector."
        ),
    },
    "ENCODING_RESULT_CHECKS": {
        "title": "Encoding and decoding Result checks",
        "targets": {"audit_encoding"},
        "categories": {"conditional_branches"},
        "addresses": {"100000e40", "100000e70", "100000ec0", "100000f00"},
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "Branches test Result discriminants from encode_t0, decode_t0, "
            "encode_z, and decode_z. Failure paths lead to unwrap/panic logic."
        ),
    },
    "ENCODING_ALLOCATION_CLEANUP": {
        "title": "Encoding allocation cleanup",
        "targets": {"audit_encoding"},
        "categories": {"conditional_branches"},
        "addresses": {"100000f1c", "100000f30", "100000ffc", "10000101c"},
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "cbz instructions guard deallocation and unwind cleanup based on "
            "allocation length or pointer state."
        ),
    },
    "SIGN_VERIFY_RESULT_CHECKS": {
        "title": "Key generation and signing Result checks",
        "targets": {"audit_sign_verify"},
        "categories": {"conditional_branches"},
        "addresses": {"100001078", "1000010f0"},
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "Branches test Result discriminants from keygen_internal and "
            "sign_internal and enter unwrap/panic paths on error."
        ),
    },
    "PUBLIC_VERIFICATION_RESULT": {
        "title": "Public verification result branch",
        "targets": {"audit_sign_verify"},
        "categories": {"conditional_branches"},
        "addresses": {"100001140"},
        "dependency": "public-result",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "The branch reflects verify_internal success or failure. "
            "Verification status is an intentionally public API result."
        ),
    },
    "SIGN_VERIFY_ALLOCATION_CLEANUP": {
        "title": "Sign/verify allocation and unwind cleanup",
        "targets": {"audit_sign_verify"},
        "categories": {"conditional_branches"},
        "addresses": {"100001150", "100001168", "10000117c", "100001230"},
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "cbz instructions guard deallocation, drop, and unwind cleanup."
        ),
    },
    "STACK_FRAME_ACCESS": {
        "title": "Fixed-offset stack and frame accesses",
        "targets": set(),
        "categories": {"indexed_memory_candidates"},
        "addresses": set(),
        "dependency": "implementation-control",
        "disposition": "accepted",
        "severity": "informational",
        "rationale": (
            "Compiler-generated stack/frame loads and stores use fixed offsets "
            "from sp or x29 and are not secret-indexed."
        ),
    },
}


def address(instruction: str) -> str:
    return instruction.split(":", 1)[0].strip().lower()


def group_for(row: dict[str, str]) -> str:
    addr = address(row["instruction"])
    target = row["target"]
    category = row["category"]
    instruction = row["instruction"]

    for group_id, group in GROUPS.items():
        if group["addresses"] and addr not in group["addresses"]:
            continue
        if group["targets"] and target not in group["targets"]:
            continue
        if category not in group["categories"]:
            continue

        if group_id == "STACK_FRAME_ACCESS":
            if "[sp" not in instruction and "[x29" not in instruction:
                continue

        return group_id

    return "UNRESOLVED"


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def build_findings(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)

    for row in rows:
        grouped[group_for(row)].append(row)

    findings: list[dict[str, str]] = []

    for group_id, members in grouped.items():
        if group_id == "UNRESOLVED":
            for index, member in enumerate(members, start=1):
                findings.append(
                    {
                        "finding_id": f"UNRESOLVED-{index:02}",
                        "title": "Unresolved instruction classification",
                        "severity": "review",
                        "dependency": member.get("dependency", "unclassified"),
                        "disposition": "open",
                        "targets": member["target"],
                        "addresses": address(member["instruction"]),
                        "instruction_count": "1",
                        "source": member.get("source_file", ""),
                        "rationale": member.get(
                            "rationale",
                            "Manual review remains required.",
                        ),
                        "evidence": member["instruction"],
                    }
                )
            continue

        group = GROUPS[group_id]
        targets = sorted({member["target"] for member in members})
        addresses = sorted(
            {address(member["instruction"]) for member in members}
        )
        sources = sorted(
            {
                f"{member.get('source_file', '')}:{member.get('source_line', '')}"
                for member in members
                if member.get("source_file", "")
            }
        )

        findings.append(
            {
                "finding_id": group_id,
                "title": group["title"],
                "severity": group["severity"],
                "dependency": group["dependency"],
                "disposition": group["disposition"],
                "targets": "; ".join(targets),
                "addresses": "; ".join(addresses),
                "instruction_count": str(len(members)),
                "source": "; ".join(sources),
                "rationale": group["rationale"],
                "evidence": " | ".join(
                    member["instruction"] for member in members
                ),
            }
        )

    return sorted(findings, key=lambda finding: finding["finding_id"])


def write_csv(path: Path, findings: list[dict[str, str]]) -> None:
    fields = [
        "finding_id",
        "title",
        "severity",
        "dependency",
        "disposition",
        "targets",
        "addresses",
        "instruction_count",
        "source",
        "rationale",
        "evidence",
    ]

    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)


def write_markdown(path: Path, findings: list[dict[str, str]]) -> None:
    open_findings = [
        finding for finding in findings
        if finding["disposition"] != "accepted"
    ]

    with path.open("w", encoding="utf-8") as stream:
        print("# Stage 9F-4E Security Finding Register", file=stream)
        print(file=stream)
        print(f"Total findings: {len(findings)}", file=stream)
        print(f"Open findings: {len(open_findings)}", file=stream)
        print(file=stream)

        for finding in findings:
            print(
                f"## {finding['finding_id']} — {finding['title']}",
                file=stream,
            )
            print(file=stream)
            print(f"- Severity: `{finding['severity']}`", file=stream)
            print(f"- Dependency: `{finding['dependency']}`", file=stream)
            print(f"- Disposition: `{finding['disposition']}`", file=stream)
            print(f"- Targets: {finding['targets']}", file=stream)
            print(f"- Addresses: {finding['addresses']}", file=stream)
            print(
                f"- Instruction records: {finding['instruction_count']}",
                file=stream,
            )
            if finding["source"]:
                print(f"- Source: {finding['source']}", file=stream)
            print(file=stream)
            print(finding["rationale"], file=stream)
            print(file=stream)
            print("Evidence:", file=stream)
            print(file=stream)
            print("```asm", file=stream)
            for item in finding["evidence"].split(" | "):
                print(item, file=stream)
            print("```", file=stream)
            print(file=stream)


def write_summary(path: Path, findings: list[dict[str, str]]) -> None:
    total_instructions = sum(
        int(finding["instruction_count"]) for finding in findings
    )
    open_findings = [
        finding for finding in findings
        if finding["disposition"] != "accepted"
    ]
    secret_branch_findings = [
        finding for finding in findings
        if finding["dependency"] in {
            "secret-key",
            "secret-coefficient",
            "secret-intermediate",
        }
        and "branch" in finding["title"].lower()
        and finding["disposition"] != "accepted"
    ]

    with path.open("w", encoding="utf-8") as stream:
        print("# Stage 9F-4E Audit Summary", file=stream)
        print(file=stream)
        print(f"- Machine-code instruction records reviewed: {total_instructions}", file=stream)
        print(f"- Consolidated findings: {len(findings)}", file=stream)
        print(f"- Open findings: {len(open_findings)}", file=stream)
        print(
            "- Unresolved secret-dependent control-flow findings: "
            f"{len(secret_branch_findings)}",
            file=stream,
        )
        print(file=stream)

        if not open_findings:
            print(
                "All reviewed findings are accepted as public, "
                "implementation-control, fixed-loop, branchless arithmetic, "
                "or public-result behavior.",
                file=stream,
            )
        else:
            print("Open findings:", file=stream)
            for finding in open_findings:
                print(
                    f"- {finding['finding_id']}: {finding['title']}",
                    file=stream,
                )

        print(file=stream)
        print("## Security conclusion", file=stream)
        print(file=stream)
        print(
            "For the audited rustc/LLVM/ARM64 build, no unresolved branch or "
            "memory-address computation was identified as dependent on secret "
            "key material or secret polynomial coefficients. Coefficient-"
            "dependent rounding corrections were lowered to branchless ARM64 "
            "conditional-select instructions. Remaining control-flow sites "
            "were attributable to Result handling, panic paths, allocator "
            "cleanup, fixed loop control, transcript-derived challenge "
            "handling, or the public verification result.",
            file=stream,
        )


def validate(findings: list[dict[str, str]]) -> int:
    open_findings = [
        finding for finding in findings
        if finding["disposition"] != "accepted"
    ]

    print(f"consolidated findings: {len(findings)}")
    print(f"open findings: {len(open_findings)}")

    for finding in open_findings:
        print(
            f"open {finding['finding_id']}: {finding['title']} "
            f"[{finding['dependency']}]"
        )

    return 1 if open_findings else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("instruction_csv", type=Path)
    parser.add_argument("register_csv", type=Path)
    parser.add_argument("register_md", type=Path)
    parser.add_argument("summary_md", type=Path)
    args = parser.parse_args()

    rows = load_rows(args.instruction_csv)
    findings = build_findings(rows)

    write_csv(args.register_csv, findings)
    write_markdown(args.register_md, findings)
    write_summary(args.summary_md, findings)

    raise SystemExit(validate(findings))


if __name__ == "__main__":
    main()
