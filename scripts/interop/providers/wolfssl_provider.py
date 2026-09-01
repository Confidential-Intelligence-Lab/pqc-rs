#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = pathlib.Path(__file__).with_name("wolfssl_bridge.c")
BIN = ROOT / "target" / "interop" / "wolfssl_bridge"

KEM_PARAMETER_SETS = [
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
]

DSA_PARAMETER_SETS = [
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
]

OPERATIONS = [
    "kem-keygen",
    "kem-encaps",
    "kem-decaps",
    "dsa-keygen",
    "dsa-sign",
    "dsa-verify",
]


def prefix() -> pathlib.Path:
    configured = os.environ.get("WOLFSSL_PREFIX")

    if configured:
        return pathlib.Path(configured)

    return ROOT / "target" / "interop" / "wolfssl-install"


def ensure_bridge() -> pathlib.Path:
    install_prefix = prefix()

    kem_header = (
        install_prefix
        / "include"
        / "wolfssl"
        / "wolfcrypt"
        / "wc_mlkem.h"
    )

    dsa_header = (
        install_prefix
        / "include"
        / "wolfssl"
        / "wolfcrypt"
        / "wc_mldsa.h"
    )

    library = install_prefix / "lib" / "libwolfssl.a"

    if not kem_header.exists():
        raise RuntimeError(
            f"wolfSSL ML-KEM header not found: {kem_header}"
        )

    if not dsa_header.exists():
        raise RuntimeError(
            f"wolfSSL ML-DSA header not found: {dsa_header}"
        )

    if not library.exists():
        raise RuntimeError(
            f"wolfSSL static library not found: {library}"
        )

    BIN.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rebuild = (
        not BIN.exists()
        or BIN.stat().st_mtime < SRC.stat().st_mtime
        or BIN.stat().st_mtime < library.stat().st_mtime
    )

    if rebuild:
        compiler = os.environ.get("CC", "cc")

        command = [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(install_prefix / "include"),
            str(SRC),
            str(library),
            "-lm",
            "-lpthread",
            "-o",
            str(BIN),
        ]

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                completed.stderr.strip()
                or "failed to compile wolfSSL bridge"
            )

    return BIN


def run_bridge(
    operation: str,
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    if parameter_set not in (
        KEM_PARAMETER_SETS + DSA_PARAMETER_SETS
    ):
        raise ValueError(
            f"unsupported parameter set {parameter_set}"
        )

    arguments = [
        str(ensure_bridge()),
        operation,
        parameter_set,
    ]

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
        arguments.extend(
            [
                str(inputs["secret_key"]),
                str(inputs["ciphertext"]),
            ]
        )

    elif operation == "dsa-keygen":
        arguments.append(
            str(inputs["xi"])
        )

    elif operation == "dsa-sign":
        arguments.extend(
            [
                str(inputs["secret_key"]),
                str(inputs["message"]),
                str(inputs["context"]),
                str(inputs["randomness"]),
            ]
        )

    elif operation == "dsa-verify":
        arguments.extend(
            [
                str(inputs["public_key"]),
                str(inputs["message"]),
                str(inputs["context"]),
                str(inputs["signature"]),
            ]
        )

    else:
        raise ValueError(
            f"unsupported operation {operation}"
        )

    completed = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
    )

    if completed.returncode != 0:
        raise RuntimeError(
            completed.stderr.strip()
            or f"wolfSSL bridge exited with {completed.returncode}"
        )

    outputs: dict[str, Any] = {}

    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        outputs[key] = value

    return outputs


def capabilities() -> list[dict[str, Any]]:
    ensure_bridge()

    return [
        {
            "algorithm": "ML-KEM",
            "parameter_sets": KEM_PARAMETER_SETS,
            "operations": [
                "roundtrip",
                "kem-keygen",
                "kem-encaps",
                "kem-decaps",
            ],
        },
        {
            "algorithm": "ML-DSA",
            "parameter_sets": DSA_PARAMETER_SETS,
            "operations": [
                "dsa-keygen",
                "dsa-sign",
                "dsa-verify",
            ],
        },
    ]


def kem_roundtrip(
    parameter_set: str,
    inputs: dict[str, Any],
) -> dict[str, Any]:
    d = str(
        inputs.get(
            "d",
            "00" * 32,
        )
    )

    z = str(
        inputs.get(
            "z",
            "01" * 32,
        )
    )

    m = str(
        inputs.get(
            "m",
            "02" * 32,
        )
    )

    keypair = run_bridge(
        "kem-keygen",
        parameter_set,
        {
            "d": d,
            "z": z,
        },
    )

    encapsulated = run_bridge(
        "kem-encaps",
        parameter_set,
        {
            "public_key": keypair["public_key"],
            "m": m,
        },
    )

    decapsulated = run_bridge(
        "kem-decaps",
        parameter_set,
        {
            "secret_key": keypair["secret_key"],
            "ciphertext": encapsulated["ciphertext"],
        },
    )

    return {
        "roundtrip": (
            encapsulated["shared_secret"]
            == decapsulated["shared_secret"]
        ),
        "public_key_length": (
            len(keypair["public_key"]) // 2
        ),
        "secret_key_length": (
            len(keypair["secret_key"]) // 2
        ),
        "ciphertext_length": (
            len(encapsulated["ciphertext"]) // 2
        ),
        "shared_secret_length": (
            len(encapsulated["shared_secret"]) // 2
        ),
    }


def execute_legacy(
    case: dict[str, Any],
) -> dict[str, Any]:
    algorithm = str(case["algorithm"])
    parameter_set = str(case["parameter_set"])
    operation = str(case["operation"])
    inputs = dict(case.get("inputs", {}))

    if algorithm not in ("ML-KEM", "ML-DSA"):
        raise ValueError(
            f"unsupported algorithm {algorithm}"
        )

    if algorithm == "ML-KEM" and operation == "roundtrip":
        return kem_roundtrip(
            parameter_set,
            inputs,
        )

    return run_bridge(
        operation,
        parameter_set,
        inputs,
    )


def execute_primitive(
    request: dict[str, Any],
) -> dict[str, Any]:
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
                "provider": "wolfssl",
                "capabilities": capabilities(),
                "outputs": {
                    "provider": "wolfssl",
                    "operations": OPERATIONS,
                },
            }

        elif "case" in request:
            response = {
                "ok": True,
                "outputs": execute_legacy(
                    dict(request["case"])
                ),
            }

        else:
            response = {
                "ok": True,
                "outputs": execute_primitive(request),
            }

        print(
            json.dumps(
                response,
                sort_keys=True,
            )
        )

        return 0

    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                },
                sort_keys=True,
            )
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
