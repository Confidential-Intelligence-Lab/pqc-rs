#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import Any


PARAMS_KEM = [
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
]

PARAMS_DSA = [
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
]

PROVIDERS = {
    "rust": [
        sys.executable,
        "scripts/interop/providers/rust_provider.py",
    ],
    "wolfssl": [
        sys.executable,
        "scripts/interop/providers/wolfssl_provider.py",
    ],
    "openssl": [
        sys.executable,
        "scripts/interop/providers/openssl_provider.py",
    ],
    "liboqs": [
        sys.executable,
        "scripts/interop/providers/liboqs_provider.py",
    ],
}

EXACT_DSA_PROVIDERS = [
    "rust",
    "wolfssl",
    "openssl",
]

ALL_PROVIDERS = [
    "rust",
    "wolfssl",
    "openssl",
    "liboqs",
]

KEM_SIZES = {
    "ML-KEM-512": {
        "public_key": 800,
        "secret_key": 1632,
        "ciphertext": 768,
        "shared_secret": 32,
    },
    "ML-KEM-768": {
        "public_key": 1184,
        "secret_key": 2400,
        "ciphertext": 1088,
        "shared_secret": 32,
    },
    "ML-KEM-1024": {
        "public_key": 1568,
        "secret_key": 3168,
        "ciphertext": 1568,
        "shared_secret": 32,
    },
}

DSA_SIZES = {
    "ML-DSA-44": {
        "public_key": 1312,
        "secret_key": 2560,
        "signature": 2420,
    },
    "ML-DSA-65": {
        "public_key": 1952,
        "secret_key": 4032,
        "signature": 3309,
    },
    "ML-DSA-87": {
        "public_key": 2592,
        "secret_key": 4896,
        "signature": 4627,
    },
}

CAPABILITY_MATRIX = {
    "rust": {
        "ml_kem_deterministic_keygen": "supported",
        "ml_kem_deterministic_encaps": "supported",
        "ml_dsa_seeded_keygen": "supported",
        "ml_dsa_explicit_signing_randomness": "supported",
        "ml_dsa_cross_verification": "supported",
    },
    "wolfssl": {
        "ml_kem_deterministic_keygen": "supported",
        "ml_kem_deterministic_encaps": "supported",
        "ml_dsa_seeded_keygen": "supported",
        "ml_dsa_explicit_signing_randomness": "supported",
        "ml_dsa_cross_verification": "supported",
    },
    "openssl": {
        "ml_kem_deterministic_keygen": "supported",
        "ml_kem_deterministic_encaps": "supported",
        "ml_dsa_seeded_keygen": "supported",
        "ml_dsa_explicit_signing_randomness": "supported",
        "ml_dsa_cross_verification": "supported",
    },
    "liboqs": {
        "ml_kem_deterministic_keygen": "supported",
        "ml_kem_deterministic_encaps": "supported",
        "ml_dsa_seeded_keygen": "unsupported_by_public_api",
        "ml_dsa_explicit_signing_randomness": "unsupported_by_public_api",
        "ml_dsa_cross_verification": "supported",
    },
}


def sha256_hex(value: str) -> str:
    return hashlib.sha256(
        bytes.fromhex(value)
    ).hexdigest()


def invoke(
    root: pathlib.Path,
    provider: str,
    operation: str,
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:

    request = {
        "protocol_version": 1,
        "action": "execute",
        "operation": operation,
        "parameter_set": parameter_set,
        "inputs": inputs,
    }

    completed = subprocess.run(
        PROVIDERS[provider],
        cwd=root,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        env=os.environ.copy(),
    )

    try:
        response = json.loads(completed.stdout)
    except Exception:
        response = None

    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
        "response": response,
    }


def call(
    root: pathlib.Path,
    provider: str,
    operation: str,
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:

    result = invoke(
        root,
        provider,
        operation,
        parameter_set,
        inputs,
    )

    response = result["response"]

    if result["returncode"] != 0:
        raise RuntimeError(
            result["stderr"].strip()
            or result["stdout"].strip()
            or (
                f"{provider}/{parameter_set}/"
                f"{operation} exited "
                f"{result['returncode']}"
            )
        )

    if response is None:
        raise RuntimeError(
            f"{provider}/{parameter_set}/{operation}: "
            "non-JSON response"
        )

    if not response.get("ok"):
        raise RuntimeError(
            str(
                response.get(
                    "error",
                    "provider rejected operation",
                )
            )
        )

    return response["outputs"]


def provider_capabilities(
    root: pathlib.Path,
    provider: str,
) -> dict[str, Any]:

    request = {
        "protocol_version": 1,
        "action": "capabilities",
    }

    completed = subprocess.run(
        PROVIDERS[provider],
        cwd=root,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        env=os.environ.copy(),
    )

    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or completed.stdout.strip()
        )

    response = json.loads(completed.stdout)

    if not response.get("ok"):
        raise RuntimeError(
            str(response.get("error"))
        )

    return response


def verification_accepted(
    result: dict[str, Any],
) -> bool:

    response = result["response"]

    if (
        result["returncode"] != 0
        or response is None
        or not response.get("ok")
    ):
        return False

    value = response.get(
        "outputs",
        {},
    ).get("valid")

    return (
        value is True
        or str(value).lower() == "true"
    )


def classify_rejection(
    result: dict[str, Any],
) -> str:

    response = result["response"]

    if (
        result["returncode"] != 0
        or response is None
        or not response.get("ok")
    ):
        return "api_reject"

    if not verification_accepted(result):
        return "cryptographic_reject"

    return "accepted"


def add_result(
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    *,
    section: str,
    case: str,
    decision: str,
    **extra: Any,
) -> None:

    record = {
        "section": section,
        "case": case,
        "decision": decision,
        **extra,
    }

    results.append(record)

    if decision == "fail":
        findings.append(
            {
                "severity": "error",
                "code": "PROVIDER_PARITY_FAILURE",
                "message": case,
            }
        )


def run_capability_gate(
    root: pathlib.Path,
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:

    observed: dict[str, Any] = {}

    for provider in ALL_PROVIDERS:
        try:
            capability = provider_capabilities(
                root,
                provider,
            )

            observed[provider] = capability

            add_result(
                results,
                findings,
                section="capabilities",
                case=f"{provider}:available",
                decision="pass",
                provider=provider,
            )

        except Exception as exc:
            observed[provider] = {
                "error": str(exc),
            }

            add_result(
                results,
                findings,
                section="capabilities",
                case=f"{provider}:available",
                decision="fail",
                provider=provider,
                reason=str(exc),
            )

    return observed


def run_ml_kem_exact(
    root: pathlib.Path,
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:

    d = "00" * 32
    z = "01" * 32
    m = "02" * 32

    for ps in PARAMS_KEM:

        size = KEM_SIZES[ps]

        keypairs: dict[str, dict[str, Any]] = {}

        for provider in ALL_PROVIDERS:
            keypairs[provider] = call(
                root,
                provider,
                "kem-keygen",
                ps,
                {
                    "d": d,
                    "z": z,
                },
            )

        reference = keypairs["rust"]

        key_exact = all(
            value["public_key"]
            == reference["public_key"]
            and value["secret_key"]
            == reference["secret_key"]
            for value in keypairs.values()
        )

        size_ok = (
            len(reference["public_key"]) // 2
            == size["public_key"]
            and len(reference["secret_key"]) // 2
            == size["secret_key"]
        )

        add_result(
            results,
            findings,
            section="ml-kem-exact",
            case=f"{ps}:exact-keygen",
            decision=(
                "pass"
                if key_exact and size_ok
                else "fail"
            ),
            parameter_set=ps,
            providers=ALL_PROVIDERS,
            public_key_sha256=sha256_hex(
                reference["public_key"]
            ),
            secret_key_sha256=sha256_hex(
                reference["secret_key"]
            ),
        )

        encapsulations: dict[
            str,
            dict[str, Any],
        ] = {}

        for provider in ALL_PROVIDERS:
            encapsulations[provider] = call(
                root,
                provider,
                "kem-encaps",
                ps,
                {
                    "public_key":
                        reference["public_key"],
                    "m": m,
                },
            )

        enc_reference = encapsulations["rust"]

        encaps_exact = all(
            value["ciphertext"]
            == enc_reference["ciphertext"]
            and value["shared_secret"]
            == enc_reference["shared_secret"]
            for value in encapsulations.values()
        )

        encaps_size_ok = (
            len(
                enc_reference["ciphertext"]
            ) // 2
            == size["ciphertext"]
            and len(
                enc_reference["shared_secret"]
            ) // 2
            == size["shared_secret"]
        )

        add_result(
            results,
            findings,
            section="ml-kem-exact",
            case=f"{ps}:exact-encapsulation",
            decision=(
                "pass"
                if encaps_exact
                and encaps_size_ok
                else "fail"
            ),
            parameter_set=ps,
            providers=ALL_PROVIDERS,
            ciphertext_sha256=sha256_hex(
                enc_reference["ciphertext"]
            ),
            shared_secret_sha256=sha256_hex(
                enc_reference["shared_secret"]
            ),
        )

        for provider in ALL_PROVIDERS:
            decapsulated = call(
                root,
                provider,
                "kem-decaps",
                ps,
                {
                    "secret_key":
                        reference["secret_key"],
                    "ciphertext":
                        enc_reference["ciphertext"],
                },
            )

            ok = (
                decapsulated["shared_secret"]
                == enc_reference["shared_secret"]
            )

            add_result(
                results,
                findings,
                section="ml-kem-cross-decapsulation",
                case=(
                    f"{ps}:rust-ciphertext:"
                    f"{provider}-decaps"
                ),
                decision=(
                    "pass" if ok else "fail"
                ),
                parameter_set=ps,
                provider=provider,
            )

        ciphertext = bytearray.fromhex(
            enc_reference["ciphertext"]
        )

        offsets = [
            0,
            len(ciphertext) // 2,
            len(ciphertext) - 1,
        ]

        for offset in offsets:

            modified = bytearray(ciphertext)
            modified[offset] ^= 0x01

            bad_ct = modified.hex()

            rejection: dict[str, str] = {}

            for provider in ALL_PROVIDERS:
                output = call(
                    root,
                    provider,
                    "kem-decaps",
                    ps,
                    {
                        "secret_key":
                            reference["secret_key"],
                        "ciphertext":
                            bad_ct,
                    },
                )

                rejection[provider] = output[
                    "shared_secret"
                ]

            rust_rejection = rejection["rust"]

            exact = all(
                value == rust_rejection
                for value in rejection.values()
            )

            not_valid = all(
                value
                != enc_reference["shared_secret"]
                for value in rejection.values()
            )

            add_result(
                results,
                findings,
                section="ml-kem-implicit-rejection",
                case=(
                    f"{ps}:ciphertext-offset-{offset}"
                ),
                decision=(
                    "pass"
                    if exact and not_valid
                    else "fail"
                ),
                parameter_set=ps,
                ciphertext_offset=offset,
                providers=ALL_PROVIDERS,
                rejection_sha256=sha256_hex(
                    rust_rejection
                ),
            )


def dsa_sign_inputs(
    provider: str,
    secret_key: str,
    message: str,
    context: str,
    randomness: str,
) -> dict[str, Any]:

    inputs: dict[str, Any] = {
        "secret_key": secret_key,
        "message": message,
        "context": context,
    }

    if provider != "liboqs":
        inputs["randomness"] = randomness

    return inputs


def run_ml_dsa_exact(
    root: pathlib.Path,
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:

    xi = "11" * 32
    randomness = "22" * 32

    message = (
        b"PQC-rs canonical provider parity"
    ).hex()

    context = (
        b"pqc-rs-provider-parity"
    ).hex()

    for ps in PARAMS_DSA:

        size = DSA_SIZES[ps]

        keypairs: dict[
            str,
            dict[str, Any],
        ] = {}

        for provider in EXACT_DSA_PROVIDERS:
            keypairs[provider] = call(
                root,
                provider,
                "dsa-keygen",
                ps,
                {
                    "xi": xi,
                },
            )

        reference = keypairs["rust"]

        keys_exact = all(
            value["public_key"]
            == reference["public_key"]
            and value["secret_key"]
            == reference["secret_key"]
            for value in keypairs.values()
        )

        size_ok = (
            len(reference["public_key"]) // 2
            == size["public_key"]
            and len(reference["secret_key"]) // 2
            == size["secret_key"]
        )

        add_result(
            results,
            findings,
            section="ml-dsa-exact",
            case=f"{ps}:exact-keygen",
            decision=(
                "pass"
                if keys_exact and size_ok
                else "fail"
            ),
            parameter_set=ps,
            providers=EXACT_DSA_PROVIDERS,
            liboqs="unsupported_by_public_api",
            public_key_sha256=sha256_hex(
                reference["public_key"]
            ),
            secret_key_sha256=sha256_hex(
                reference["secret_key"]
            ),
        )

        signatures: dict[str, str] = {}

        for provider in EXACT_DSA_PROVIDERS:
            output = call(
                root,
                provider,
                "dsa-sign",
                ps,
                dsa_sign_inputs(
                    provider,
                    reference["secret_key"],
                    message,
                    context,
                    randomness,
                ),
            )

            signatures[provider] = output[
                "signature"
            ]

        rust_signature = signatures["rust"]

        signatures_exact = all(
            value == rust_signature
            for value in signatures.values()
        )

        sig_size_ok = (
            len(rust_signature) // 2
            == size["signature"]
        )

        add_result(
            results,
            findings,
            section="ml-dsa-exact",
            case=f"{ps}:exact-signature",
            decision=(
                "pass"
                if signatures_exact
                and sig_size_ok
                else "fail"
            ),
            parameter_set=ps,
            providers=EXACT_DSA_PROVIDERS,
            liboqs="unsupported_by_public_api",
            signature_sha256=sha256_hex(
                rust_signature
            ),
        )

        for provider in ALL_PROVIDERS:
            output = call(
                root,
                provider,
                "dsa-verify",
                ps,
                {
                    "public_key":
                        reference["public_key"],
                    "message":
                        message,
                    "context":
                        context,
                    "signature":
                        rust_signature,
                },
            )

            valid = (
                output.get("valid") is True
                or str(
                    output.get("valid")
                ).lower() == "true"
            )

            add_result(
                results,
                findings,
                section="ml-dsa-semantic",
                case=(
                    f"{ps}:rust-signature:"
                    f"{provider}-verify"
                ),
                decision=(
                    "pass"
                    if valid
                    else "fail"
                ),
                parameter_set=ps,
                provider=provider,
            )

        liboqs_signature = call(
            root,
            "liboqs",
            "dsa-sign",
            ps,
            dsa_sign_inputs(
                "liboqs",
                reference["secret_key"],
                message,
                context,
                randomness,
            ),
        )["signature"]

        for provider in ALL_PROVIDERS:
            output = call(
                root,
                provider,
                "dsa-verify",
                ps,
                {
                    "public_key":
                        reference["public_key"],
                    "message":
                        message,
                    "context":
                        context,
                    "signature":
                        liboqs_signature,
                },
            )

            valid = (
                output.get("valid") is True
                or str(
                    output.get("valid")
                ).lower() == "true"
            )

            add_result(
                results,
                findings,
                section="ml-dsa-semantic",
                case=(
                    f"{ps}:liboqs-signature:"
                    f"{provider}-verify"
                ),
                decision=(
                    "pass"
                    if valid
                    else "fail"
                ),
                parameter_set=ps,
                provider=provider,
            )


def run_ml_dsa_boundaries_and_negative(
    root: pathlib.Path,
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:

    xi_a = "31" * 32
    xi_b = "32" * 32
    randomness = "33" * 32

    message = (
        b"provider parity negative semantics"
    ).hex()

    bad_message = (
        b"provider parity NEGATIVE semantics"
    ).hex()

    context = (
        b"provider-parity"
    ).hex()

    bad_context = (
        b"provider-parity-mutated"
    ).hex()

    context_255 = bytes(
        (i * 13 + 7) & 0xff
        for i in range(255)
    ).hex()

    context_256 = bytes(
        (i * 17 + 3) & 0xff
        for i in range(256)
    ).hex()

    for ps in PARAMS_DSA:

        sig_size = DSA_SIZES[ps][
            "signature"
        ]

        keys_a = call(
            root,
            "rust",
            "dsa-keygen",
            ps,
            {
                "xi": xi_a,
            },
        )

        keys_b = call(
            root,
            "rust",
            "dsa-keygen",
            ps,
            {
                "xi": xi_b,
            },
        )

        sig_255 = call(
            root,
            "rust",
            "dsa-sign",
            ps,
            dsa_sign_inputs(
                "rust",
                keys_a["secret_key"],
                message,
                context_255,
                randomness,
            ),
        )["signature"]

        for provider in ALL_PROVIDERS:
            result = invoke(
                root,
                provider,
                "dsa-verify",
                ps,
                {
                    "public_key":
                        keys_a["public_key"],
                    "message":
                        message,
                    "context":
                        context_255,
                    "signature":
                        sig_255,
                },
            )

            add_result(
                results,
                findings,
                section="ml-dsa-boundary",
                case=(
                    f"{ps}:255-byte-context:"
                    f"{provider}"
                ),
                decision=(
                    "pass"
                    if verification_accepted(
                        result
                    )
                    else "fail"
                ),
                parameter_set=ps,
                provider=provider,
            )

        baseline_sig = call(
            root,
            "rust",
            "dsa-sign",
            ps,
            dsa_sign_inputs(
                "rust",
                keys_a["secret_key"],
                message,
                context,
                randomness,
            ),
        )["signature"]

        negative_cases = [
            (
                "modified-message",
                {
                    "public_key":
                        keys_a["public_key"],
                    "message":
                        bad_message,
                    "context":
                        context,
                    "signature":
                        baseline_sig,
                },
            ),
            (
                "modified-context",
                {
                    "public_key":
                        keys_a["public_key"],
                    "message":
                        message,
                    "context":
                        bad_context,
                    "signature":
                        baseline_sig,
                },
            ),
            (
                "wrong-public-key",
                {
                    "public_key":
                        keys_b["public_key"],
                    "message":
                        message,
                    "context":
                        context,
                    "signature":
                        baseline_sig,
                },
            ),
        ]

        for name, inputs in negative_cases:
            for provider in ALL_PROVIDERS:
                result = invoke(
                    root,
                    provider,
                    "dsa-verify",
                    ps,
                    inputs,
                )

                mode = classify_rejection(
                    result
                )

                add_result(
                    results,
                    findings,
                    section="ml-dsa-negative",
                    case=(
                        f"{ps}:{name}:"
                        f"{provider}"
                    ),
                    decision=(
                        "pass"
                        if mode
                        != "accepted"
                        else "fail"
                    ),
                    parameter_set=ps,
                    provider=provider,
                    rejection_mode=mode,
                )

        signature_bytes = bytearray.fromhex(
            baseline_sig
        )

        offsets = [
            0,
            sig_size // 2,
            sig_size - 1,
        ]

        for offset in offsets:

            modified = bytearray(
                signature_bytes
            )

            modified[offset] ^= 0x01

            inputs = {
                "public_key":
                    keys_a["public_key"],
                "message":
                    message,
                "context":
                    context,
                "signature":
                    modified.hex(),
            }

            for provider in ALL_PROVIDERS:
                result = invoke(
                    root,
                    provider,
                    "dsa-verify",
                    ps,
                    inputs,
                )

                mode = classify_rejection(
                    result
                )

                add_result(
                    results,
                    findings,
                    section="ml-dsa-negative",
                    case=(
                        f"{ps}:signature-mutation-"
                        f"{offset}:{provider}"
                    ),
                    decision=(
                        "pass"
                        if mode
                        != "accepted"
                        else "fail"
                    ),
                    parameter_set=ps,
                    provider=provider,
                    rejection_mode=mode,
                )

        for label, signature in [
            (
                "short-signature",
                bytes.fromhex(
                    baseline_sig
                )[:-1].hex(),
            ),
            (
                "long-signature",
                baseline_sig + "00",
            ),
        ]:
            inputs = {
                "public_key":
                    keys_a["public_key"],
                "message":
                    message,
                "context":
                    context,
                "signature":
                    signature,
            }

            for provider in ALL_PROVIDERS:
                result = invoke(
                    root,
                    provider,
                    "dsa-verify",
                    ps,
                    inputs,
                )

                mode = classify_rejection(
                    result
                )

                add_result(
                    results,
                    findings,
                    section="ml-dsa-negative",
                    case=(
                        f"{ps}:{label}:"
                        f"{provider}"
                    ),
                    decision=(
                        "pass"
                        if mode
                        != "accepted"
                        else "fail"
                    ),
                    parameter_set=ps,
                    provider=provider,
                    rejection_mode=mode,
                )

        oversized_inputs = {
            "public_key":
                keys_a["public_key"],
            "message":
                message,
            "context":
                context_256,
            "signature":
                baseline_sig,
        }

        for provider in ALL_PROVIDERS:
            result = invoke(
                root,
                provider,
                "dsa-verify",
                ps,
                oversized_inputs,
            )

            mode = classify_rejection(
                result
            )

            add_result(
                results,
                findings,
                section="ml-dsa-boundary",
                case=(
                    f"{ps}:256-byte-context:"
                    f"{provider}"
                ),
                decision=(
                    "pass"
                    if mode
                    != "accepted"
                    else "fail"
                ),
                parameter_set=ps,
                provider=provider,
                rejection_mode=mode,
            )


def run_ml_dsa_cross_parameter(
    root: pathlib.Path,
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:

    pairs = [
        (
            "ML-DSA-44",
            "ML-DSA-65",
        ),
        (
            "ML-DSA-65",
            "ML-DSA-87",
        ),
        (
            "ML-DSA-87",
            "ML-DSA-44",
        ),
    ]

    message = (
        b"cross parameter misuse"
    ).hex()

    context = b"ctx".hex()

    for source, target in pairs:

        keys = call(
            root,
            "rust",
            "dsa-keygen",
            source,
            {
                "xi": "55" * 32,
            },
        )

        signature = call(
            root,
            "rust",
            "dsa-sign",
            source,
            dsa_sign_inputs(
                "rust",
                keys["secret_key"],
                message,
                context,
                "aa" * 32,
            ),
        )["signature"]

        for provider in ALL_PROVIDERS:

            result = invoke(
                root,
                provider,
                "dsa-verify",
                target,
                {
                    "public_key":
                        keys["public_key"],
                    "message":
                        message,
                    "context":
                        context,
                    "signature":
                        signature,
                },
            )

            mode = classify_rejection(
                result
            )

            add_result(
                results,
                findings,
                section="ml-dsa-cross-parameter",
                case=(
                    f"{source}-as-{target}:"
                    f"{provider}"
                ),
                decision=(
                    "pass"
                    if mode != "accepted"
                    else "fail"
                ),
                source_parameter_set=source,
                target_parameter_set=target,
                provider=provider,
                rejection_mode=mode,
            )


def write_reports(
    output: pathlib.Path,
    *,
    strict: bool,
    capabilities: dict[str, Any],
    results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> str:

    passed = sum(
        item["decision"] == "pass"
        for item in results
    )

    failed = sum(
        item["decision"] == "fail"
        for item in results
    )

    decision = (
        "pass"
        if failed == 0
        else "fail"
    )

    report = {
        "schema_version": 2,
        "generated_at": (
            dt.datetime.now(
                dt.timezone.utc
            ).isoformat()
        ),
        "decision": decision,
        "strict": strict,
        "summary": {
            "executed": len(results),
            "passed": passed,
            "failed": failed,
        },
        "providers": {
            "observed": capabilities,
            "capability_matrix":
                CAPABILITY_MATRIX,
        },
        "results": results,
        "findings": findings,
        "claim_boundary": (
            "A pass demonstrates the tested "
            "software-provider interoperability "
            "properties for PQC-rs, wolfSSL, "
            "OpenSSL, and liboqs. ML-KEM "
            "deterministic equivalence covers "
            "ML-KEM-512/768/1024, including "
            "implicit rejection. ML-DSA exact "
            "seeded equivalence covers PQC-rs, "
            "wolfSSL, and OpenSSL; liboqs is "
            "included in raw-key/signature, "
            "context-bound, negative, and "
            "cross-parameter interoperability "
            "tests because its public API does "
            "not expose deterministic ML-DSA "
            "key generation or explicit signing "
            "randomness."
        ),
    }

    output.mkdir(
        parents=True,
        exist_ok=True,
    )

    (
        output
        / "report.json"
    ).write_text(
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    lines = [
        "# Software Provider Parity Report",
        "",
        f"- Decision: **{decision}**",
        f"- Executed: {len(results)}",
        f"- Passed: {passed}",
        f"- Failed: {failed}",
        "",
        "## Provider capability matrix",
        "",
        "| Capability | PQC-rs | wolfSSL | OpenSSL | liboqs |",
        "|---|---|---|---|---|",
    ]

    capability_labels = [
        (
            "ML-KEM deterministic keygen",
            "ml_kem_deterministic_keygen",
        ),
        (
            "ML-KEM deterministic encapsulation",
            "ml_kem_deterministic_encaps",
        ),
        (
            "ML-DSA seeded keygen",
            "ml_dsa_seeded_keygen",
        ),
        (
            "ML-DSA explicit signing randomness",
            "ml_dsa_explicit_signing_randomness",
        ),
        (
            "ML-DSA cross-verification",
            "ml_dsa_cross_verification",
        ),
    ]

    for label, key in capability_labels:
        lines.append(
            "| "
            + label
            + " | "
            + " | ".join(
                CAPABILITY_MATRIX[
                    provider
                ][key]
                for provider
                in ALL_PROVIDERS
            )
            + " |"
        )

    lines += [
        "",
        "## Results",
        "",
        "| Section | Case | Decision |",
        "|---|---|---|",
    ]

    for item in results:
        lines.append(
            f"| {item['section']} | "
            f"`{item['case']}` | "
            f"**{item['decision']}** |"
        )

    lines += [
        "",
        "## Findings",
        "",
    ]

    if findings:
        for finding in findings:
            lines.append(
                f"- **{finding['code']}**: "
                f"{finding['message']}"
            )
    else:
        lines.append("No findings.")

    lines += [
        "",
        "## Claim boundary",
        "",
        report["claim_boundary"],
        "",
    ]

    (
        output
        / "report.md"
    ).write_text(
        "\n".join(lines)
    )

    print(
        f"decision={decision}"
    )
    print(
        f"executed={len(results)}"
    )
    print(
        f"passed={passed}"
    )
    print(
        f"failed={failed}"
    )
    print(
        f"report={output / 'report.md'}"
    )

    return decision


def main() -> int:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        default=".",
    )

    parser.add_argument(
        "--output",
        default="target/interop-cross",
    )

    parser.add_argument(
        "--strict",
        action="store_true",
    )

    args = parser.parse_args()

    root = pathlib.Path(
        args.root
    ).resolve()

    output = root / args.output

    results: list[
        dict[str, Any]
    ] = []

    findings: list[
        dict[str, Any]
    ] = []

    try:
        capabilities = run_capability_gate(
            root,
            results,
            findings,
        )

        if any(
            item["decision"] == "fail"
            for item in results
            if item["section"]
            == "capabilities"
        ):
            decision = write_reports(
                output,
                strict=args.strict,
                capabilities=capabilities,
                results=results,
                findings=findings,
            )

            return (
                1
                if decision == "fail"
                else 0
            )

        run_ml_kem_exact(
            root,
            results,
            findings,
        )

        run_ml_dsa_exact(
            root,
            results,
            findings,
        )

        run_ml_dsa_boundaries_and_negative(
            root,
            results,
            findings,
        )

        run_ml_dsa_cross_parameter(
            root,
            results,
            findings,
        )

    except Exception as exc:
        findings.append(
            {
                "severity": "error",
                "code": "PARITY_ENGINE_EXCEPTION",
                "message": str(exc),
            }
        )

        add_result(
            results,
            findings,
            section="engine",
            case="unhandled-exception",
            decision="fail",
            reason=str(exc),
        )

        capabilities = locals().get(
            "capabilities",
            {},
        )

    decision = write_reports(
        output,
        strict=args.strict,
        capabilities=capabilities,
        results=results,
        findings=findings,
    )

    return (
        0
        if decision == "pass"
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
