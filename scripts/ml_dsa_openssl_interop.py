#!/usr/bin/env python3
"""Bidirectional Pure ML-DSA interoperability with OpenSSL 3.5+."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess

from openssl_provider_interop import PROVIDERS, call, seed

PARAMETER_SETS = {
    "ML-DSA-44": {"public_key": 1312, "private_key": 2560, "signature": 2420},
    "ML-DSA-65": {"public_key": 1952, "private_key": 4032, "signature": 3309},
    "ML-DSA-87": {"public_key": 2592, "private_key": 4896, "signature": 4627},
}


def provider_metadata(root: pathlib.Path, provider: str) -> dict:
    request = {"protocol_version": 1, "action": "capabilities"}
    completed = subprocess.run(
        PROVIDERS[provider],
        cwd=root,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        env=os.environ.copy(),
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    response = json.loads(completed.stdout)
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error")))
    return {
        "provider": provider,
        "version": response.get("outputs", {}).get("version", "repository-native"),
        "capabilities": response.get("capabilities", []),
    }


def mutate_hex(value: str) -> str:
    if len(value) < 2:
        raise ValueError("cannot mutate an empty artifact")
    first = int(value[:2], 16) ^ 1
    return f"{first:02x}{value[2:]}"


def require_size(label: str, value: str, expected: int) -> None:
    if len(value) != expected * 2:
        raise RuntimeError(
            f"{label} has {len(value) // 2} bytes; expected {expected}"
        )


def verification_case(
    root: pathlib.Path,
    parameter_set: str,
    producer: str,
    consumer: str,
    public_key: str,
    message: str,
    context: str,
    signature: str,
    mutation: str,
) -> dict:
    case_message = message
    case_context = context
    case_signature = signature
    expected = True

    if mutation == "message":
        case_message = mutate_hex(message)
        expected = False
    elif mutation == "context":
        case_context = context + "00"
        expected = False
    elif mutation == "signature":
        case_signature = mutate_hex(signature)
        expected = False
    elif mutation != "none":
        raise ValueError(f"unsupported mutation: {mutation}")

    output = call(
        root,
        consumer,
        "dsa-verify",
        parameter_set,
        {
            "public_key": public_key,
            "message": case_message,
            "context": case_context,
            "signature": case_signature,
        },
    )
    observed = bool(output["valid"])
    return {
        "case": f"{parameter_set}:{producer}->{consumer}:{mutation}",
        "parameter_set": parameter_set,
        "producer": producer,
        "consumer": consumer,
        "mutation": mutation,
        "expected_valid": expected,
        "observed_valid": observed,
        "decision": "pass" if observed == expected else "fail",
    }


def direction_cases(
    root: pathlib.Path,
    parameter_set: str,
    producer: str,
    consumer: str,
) -> list[dict]:
    sizes = PARAMETER_SETS[parameter_set]
    message = seed(parameter_set + "-stage15a7-message")
    context = "737461676531356137"

    if producer == "rust":
        key_pair = call(
            root,
            "rust",
            "dsa-keygen",
            parameter_set,
            {"xi": seed(parameter_set + "-stage15a7-xi")},
        )
        signature = call(
            root,
            "rust",
            "dsa-sign",
            parameter_set,
            {
                "secret_key": key_pair["secret_key"],
                "message": message,
                "context": context,
                "randomness": "00" * 32,
            },
        )["signature"]
    else:
        key_pair = call(root, "openssl", "dsa-keygen", parameter_set, {})
        signature = call(
            root,
            "openssl",
            "dsa-sign",
            parameter_set,
            {
                "secret_key": key_pair["secret_key"],
                "public_key": key_pair["public_key"],
                "message": message,
                "context": context,
            },
        )["signature"]

    require_size("public key", key_pair["public_key"], sizes["public_key"])
    require_size("private key", key_pair["secret_key"], sizes["private_key"])
    require_size("signature", signature, sizes["signature"])

    return [
        verification_case(
            root,
            parameter_set,
            producer,
            consumer,
            key_pair["public_key"],
            message,
            context,
            signature,
            mutation,
        )
        for mutation in ("none", "message", "context", "signature")
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="target/interop-openssl-mldsa")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    results: list[dict] = []
    findings: list[dict] = []
    providers: list[dict] = []

    try:
        providers = [
            provider_metadata(root, "rust"),
            provider_metadata(root, "openssl"),
        ]
        for parameter_set in PARAMETER_SETS:
            results.extend(direction_cases(root, parameter_set, "rust", "openssl"))
            results.extend(direction_cases(root, parameter_set, "openssl", "rust"))
    except Exception as error:
        findings.append(
            {
                "severity": "error",
                "code": "OPENSSL_ML_DSA_EXECUTION_FAILED",
                "message": str(error),
            }
        )

    for result in results:
        if result["decision"] != "pass":
            findings.append(
                {
                    "severity": "error",
                    "code": "OPENSSL_ML_DSA_VERIFICATION_MISMATCH",
                    "message": result["case"],
                }
            )

    expected_cases = len(PARAMETER_SETS) * 2 * 4
    passed = sum(result["decision"] == "pass" for result in results)
    failed = len(results) - passed
    complete = len(results) == expected_cases
    if not complete:
        findings.append(
            {
                "severity": "error",
                "code": "OPENSSL_ML_DSA_INCOMPLETE",
                "message": f"executed {len(results)} of {expected_cases} required cases",
            }
        )
    decision = "pass" if complete and failed == 0 and not findings else "fail"

    report = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "decision": decision,
        "strict": args.strict,
        "providers": providers,
        "summary": {
            "expected": expected_cases,
            "executed": len(results),
            "passed": passed,
            "failed": failed,
        },
        "results": results,
        "findings": findings,
        "claim_boundary": (
            "A pass demonstrates bidirectional Pure ML-DSA signature "
            "cross-verification for ML-DSA-44, ML-DSA-65, and ML-DSA-87 "
            "between this PQC-rs revision and the recorded OpenSSL provider. "
            "It also demonstrates rejection of the tested wrong-message, "
            "wrong-context, and single-bit signature mutations. It is not "
            "HashML-DSA evidence, certification, or a general security proof."
        ),
    }

    output = root / args.output
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    provider_lines = [
        f"- `{provider['provider']}`: {provider['version']}" for provider in providers
    ]
    result_lines = [
        "| Parameter set | Producer | Consumer | Mutation | Expected | Observed | Decision |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for result in results:
        result_lines.append(
            f"| `{result['parameter_set']}` | `{result['producer']}` | "
            f"`{result['consumer']}` | `{result['mutation']}` | "
            f"`{str(result['expected_valid']).lower()}` | "
            f"`{str(result['observed_valid']).lower()}` | "
            f"**{result['decision']}** |"
        )
    finding_lines = (
        [f"- **{finding['code']}**: {finding['message']}" for finding in findings]
        if findings
        else ["No findings."]
    )
    markdown = "\n".join(
        [
            "# OpenSSL ML-DSA Interoperability Report",
            "",
            f"- Decision: **{decision}**",
            f"- Expected: {expected_cases}",
            f"- Executed: {len(results)}",
            f"- Passed: {passed}",
            f"- Failed: {failed}",
            "",
            "## Providers",
            "",
            *(provider_lines or ["Provider discovery failed."]),
            "",
            "## Verification cases",
            "",
            *result_lines,
            "",
            "## Findings",
            "",
            *finding_lines,
            "",
            "## Claim boundary",
            "",
            report["claim_boundary"],
            "",
        ]
    )
    (output / "report.md").write_text(markdown)

    print(f"decision={decision}")
    print(f"expected={expected_cases}")
    print(f"executed={len(results)}")
    print(f"passed={passed}")
    print(f"failed={failed}")
    print(f"report={output / 'report.md'}")
    return 0 if decision == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
