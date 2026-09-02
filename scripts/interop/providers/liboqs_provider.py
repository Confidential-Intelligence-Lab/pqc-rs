#!/usr/bin/env python3
"""Dual-protocol liboqs provider for A2.2 smoke and A2.3 cross-provider tests."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = pathlib.Path(__file__).with_name("liboqs_bridge.c")
BIN = ROOT / "target" / "interop" / "liboqs_bridge"

KEM_PARAMETER_SETS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
DSA_PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


def prefix() -> pathlib.Path:
    configured = os.environ.get("OQS_PREFIX")
    if configured:
        return pathlib.Path(configured)
    library = os.environ.get("OQS_LIBOQS_PATH")
    if library:
        return pathlib.Path(library).resolve().parent.parent
    if pathlib.Path("/opt/homebrew/include/oqs/oqs.h").exists():
        return pathlib.Path("/opt/homebrew")
    return pathlib.Path("/usr/local")


def ensure_bridge() -> pathlib.Path:
    install_prefix = prefix()
    BIN.parent.mkdir(parents=True, exist_ok=True)
    if not BIN.exists() or BIN.stat().st_mtime < SRC.stat().st_mtime:
        compiler = os.environ.get("CC", "cc")
        command = [
            compiler,
            "-std=c11",
            str(SRC),
            "-I",
            str(install_prefix / "include"),
            "-L",
            str(install_prefix / "lib"),
            f"-Wl,-rpath,{install_prefix / 'lib'}",
            "-loqs",
            "-o",
            str(BIN),
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "failed to compile liboqs bridge")
    return BIN


def run_bridge(operation: str, parameter_set: str, inputs: dict[str, Any]) -> dict[str, Any]:
    arguments = [str(ensure_bridge()), operation, parameter_set]
    if operation == "kem-keygen":
        arguments.extend(
            [
                str(inputs["d"]),
                str(inputs["z"]),
            ]
        )
    elif operation == "kem-encaps":
        arguments.extend(
            [
                str(inputs["public_key"]),
                str(inputs["m"]),
            ]
        )
    elif operation == "kem-decaps":
        arguments.extend([str(inputs["secret_key"]), str(inputs["ciphertext"])])
    elif operation == "dsa-sign":
        arguments.extend(
            [
                str(inputs["secret_key"]),
                str(inputs["message"]),
                str(inputs.get("context", "")),
            ]
        )
    elif operation == "dsa-verify":
        arguments.extend(
            [
                str(inputs["public_key"]),
                str(inputs["message"]),
                str(inputs.get("context", "")),
                str(inputs["signature"]),
            ]
        )

    completed = subprocess.run(arguments, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"bridge exited with {completed.returncode}")

    outputs: dict[str, Any] = {}
    for line in completed.stdout.splitlines():
        key, value = line.split("=", 1)
        outputs[key] = value == "true" if key == "valid" else value
    return outputs


def capabilities() -> list[dict[str, Any]]:
    ensure_bridge()
    return [
        {
            "algorithm": "ML-KEM",
            "parameter_sets": KEM_PARAMETER_SETS,
            "operations": ["roundtrip", "kem-keygen", "kem-encaps", "kem-decaps"],
        },
        {
            "algorithm": "ML-DSA",
            "parameter_sets": DSA_PARAMETER_SETS,
            "operations": ["roundtrip", "dsa-keygen", "dsa-sign", "dsa-verify"],
        },
    ]


def kem_roundtrip(parameter_set: str) -> dict[str, Any]:
    keypair = run_bridge(
        "kem-keygen",
        parameter_set,
        {
            "d": "00" * 32,
            "z": "01" * 32,
        },
    )
    encapsulated = run_bridge(
        "kem-encaps",
        parameter_set,
        {
            "public_key": keypair["public_key"],
            "m": "02" * 32,
        },
    )
    decapsulated = run_bridge(
        "kem-decaps",
        parameter_set,
        {"secret_key": keypair["secret_key"], "ciphertext": encapsulated["ciphertext"]},
    )
    return {
        "roundtrip": encapsulated["shared_secret"] == decapsulated["shared_secret"],
        "public_key_length": len(keypair["public_key"]) // 2,
        "secret_key_length": len(keypair["secret_key"]) // 2,
        "ciphertext_length": len(encapsulated["ciphertext"]) // 2,
        "shared_secret_length": len(encapsulated["shared_secret"]) // 2,
    }


def dsa_roundtrip(parameter_set: str, inputs: dict[str, Any]) -> dict[str, Any]:
    message = str(inputs.get("message", ""))
    context = str(inputs.get("context", ""))
    keypair = run_bridge("dsa-keygen", parameter_set, {})
    signed = run_bridge(
        "dsa-sign",
        parameter_set,
        {"secret_key": keypair["secret_key"], "message": message, "context": context},
    )
    verified = run_bridge(
        "dsa-verify",
        parameter_set,
        {
            "public_key": keypair["public_key"],
            "message": message,
            "context": context,
            "signature": signed["signature"],
        },
    )
    return {
        "roundtrip": bool(verified["valid"]),
        "public_key_length": len(keypair["public_key"]) // 2,
        "secret_key_length": len(keypair["secret_key"]) // 2,
        "signature_length": len(signed["signature"]) // 2,
    }


def execute_legacy(case: dict[str, Any]) -> dict[str, Any]:
    algorithm = str(case["algorithm"])
    parameter_set = str(case["parameter_set"])
    operation = str(case["operation"])
    inputs = dict(case.get("inputs", {}))
    if operation != "roundtrip":
        return run_bridge(operation, parameter_set, inputs)
    if algorithm == "ML-KEM":
        return kem_roundtrip(parameter_set)
    if algorithm == "ML-DSA":
        return dsa_roundtrip(parameter_set, inputs)
    raise ValueError(f"unsupported roundtrip algorithm: {algorithm}")


def execute_primitive(request: dict[str, Any]) -> dict[str, Any]:
    return run_bridge(
        str(request["operation"]),
        str(request["parameter_set"]),
        dict(request.get("inputs", {})),
    )


def main() -> int:
    try:
        request = json.load(sys.stdin)
        action = request.get("action")
        if action == "capabilities":
            response = {
                "ok": True,
                "provider": "liboqs",
                "capabilities": capabilities(),
                "outputs": {
                    "provider": "liboqs",
                    "operations": [
                        "kem-keygen",
                        "kem-encaps",
                        "kem-decaps",
                        "dsa-keygen",
                        "dsa-sign",
                        "dsa-verify",
                    ],
                },
            }
        elif "case" in request:
            response = {"ok": True, "outputs": execute_legacy(dict(request["case"]))}
        else:
            response = {"ok": True, "outputs": execute_primitive(request)}
        print(json.dumps(response, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
